package client

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/gorilla/websocket"

	"github.com/genericwsserver/client-sdk/types"
)

func (c *Client) readPump() {
	defer c.wg.Done()

	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn == nil {
		return
	}

	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		c.logDebug("Received pong")
		return nil
	})

	defer func() {
		c.handleDisconnect(nil)
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		messageType, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.logError("WebSocket read error: %v", err)
				c.metrics.errorsCount.Add(1)
			}
			c.handleDisconnect(err)
			return
		}

		if messageType != websocket.TextMessage {
			continue
		}

		var msg types.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			c.logError("Failed to unmarshal message: %v", err)
			c.metrics.errorsCount.Add(1)
			select {
			case c.errorChan <- fmt.Errorf("unmarshal error: %w", err):
			default:
			}
			continue
		}

		// Debug: Log if message has encryption fields
		if msg.Header.EncryptedKey != "" || msg.Header.EncryptionNonce != "" {
			keyPreview := msg.Header.EncryptedKey
			if len(keyPreview) > 20 {
				keyPreview = keyPreview[:20] + "..."
			}
			c.logDebug("Received encrypted message - Key: %s, Nonce: %s",
				keyPreview, msg.Header.EncryptionNonce)
		}

		// Decrypt the message if it's encrypted (has encrypted key)
		if msg.Header.EncryptedKey != "" {
			c.logDebug("Message from %s has encrypted key, attempting decryption", msg.Header.From)
			decryptedContent, err := c.decryptMessage(&msg)
			if err != nil {
				c.logError("Failed to decrypt message from %s: %v", msg.Header.From, err)
				c.metrics.errorsCount.Add(1)
				select {
				case c.errorChan <- fmt.Errorf("decryption error: %w", err):
				default:
				}
				continue
			}
			// Replace encrypted content with decrypted content
			msg.Body.Content = decryptedContent
			c.logDebug("Successfully decrypted message from %s", msg.Header.From)
		} else {
			c.logDebug("Message from %s is not encrypted (no encrypted key)", msg.Header.From)
		}

		c.metrics.messagesReceived.Add(1)
		c.logDebug("Received message from %s", msg.Header.From)

		select {
		case c.receiveChan <- &msg:
		default:
			c.logError("Receive channel full, dropping message")
		}

		c.processMessage(&msg)
	}
}

func (c *Client) writePump() {
	defer c.wg.Done()

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case msg := <-c.sendChan:
			c.connLock.RLock()
			conn := c.conn
			c.connLock.RUnlock()

			if conn == nil {
				continue
			}

			conn.SetWriteDeadline(time.Now().Add(writeWait))

			data, err := json.Marshal(msg)
			if err != nil {
				c.logError("Failed to marshal message: %v", err)
				c.metrics.errorsCount.Add(1)
				continue
			}

			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				c.logError("Failed to send message: %v", err)
				c.metrics.errorsCount.Add(1)
				c.handleDisconnect(err)
				return
			}

			c.logDebug("Sent message to %s", msg.Header.To)

		case <-ticker.C:
			c.connLock.RLock()
			conn := c.conn
			c.connLock.RUnlock()

			if conn == nil {
				continue
			}

			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.logError("Failed to send ping: %v", err)
				c.handleDisconnect(err)
				return
			}
			c.logDebug("Sent ping")
		}
	}
}

func (c *Client) processMessage(msg *types.Message) {
	select {
	case <-c.workerPool:
		go func() {
			defer func() {
				c.workerPool <- struct{}{}
				if r := recover(); r != nil {
					c.logError("Panic in message handler: %v", r)
					c.metrics.errorsCount.Add(1)
				}
			}()

			c.handlersLock.RLock()
			handlers := make([]types.MessageHandler, len(c.messageHandlers))
			copy(handlers, c.messageHandlers)
			c.handlersLock.RUnlock()

			for _, handler := range handlers {
				if err := handler.HandleMessage(msg); err != nil {
					c.logError("Message handler error: %v", err)
					select {
					case c.errorChan <- fmt.Errorf("handler error: %w", err):
					default:
					}
				}
			}
		}()
	default:
		c.logDebug("Worker pool exhausted, processing message synchronously")
		c.handlersLock.RLock()
		handlers := make([]types.MessageHandler, len(c.messageHandlers))
		copy(handlers, c.messageHandlers)
		c.handlersLock.RUnlock()

		for _, handler := range handlers {
			if err := handler.HandleMessage(msg); err != nil {
				c.logError("Message handler error: %v", err)
				select {
				case c.errorChan <- fmt.Errorf("handler error: %w", err):
				default:
				}
			}
		}
	}
}

func (c *Client) handleDisconnect(err error) {
	if !c.compareAndSwapState(types.StateConnected, types.StateDisconnected) {
		return
	}

	c.connLock.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connLock.Unlock()

	if c.onDisconnect != nil {
		go c.onDisconnect(err)
	}

	if c.config.AutoReconnect && c.ctx.Err() == nil {
		c.scheduleReconnect()
	}
}

func (c *Client) scheduleReconnect() {
	if !c.compareAndSwapState(types.StateDisconnected, types.StateReconnecting) {
		return
	}

	c.metrics.reconnectCount.Add(1)
	attempt := c.metrics.reconnectCount.Load()

	jitter := time.Duration(rand.Float64() * float64(c.reconnectDelay) * 0.3)
	delay := c.reconnectDelay + jitter

	if delay > c.config.MaxReconnectWait {
		delay = c.config.MaxReconnectWait
	}

	c.logDebug("Scheduling reconnect attempt %d in %v", attempt, delay)

	if c.onReconnect != nil {
		go c.onReconnect(int(attempt))
	}

	c.reconnectTimer = time.AfterFunc(delay, func() {
		if c.ctx.Err() != nil {
			return
		}

		c.logDebug("Attempting reconnect #%d", attempt)

		if err := c.Connect(); err != nil {
			c.logError("Reconnect attempt %d failed: %v", attempt, err)

			c.reconnectDelay = time.Duration(float64(c.reconnectDelay) * 1.5)
			if c.reconnectDelay > c.config.MaxReconnectWait {
				c.reconnectDelay = c.config.MaxReconnectWait
			}
		} else {
			c.logDebug("Reconnect attempt %d successful", attempt)
			c.metrics.reconnectCount.Store(0)
		}
	})
}

func (c *Client) setState(state types.ConnectionState) {
	c.state.Store(int32(state))
	c.logDebug("State changed to: %s", state)
}

func (c *Client) compareAndSwapState(old, newState types.ConnectionState) bool {
	return c.state.CompareAndSwap(int32(old), int32(newState))
}

func (c *Client) logDebug(format string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Printf("[DEBUG] "+format, args...)
	}
}

func (c *Client) logError(format string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Printf("[ERROR] "+format, args...)
	}
}
