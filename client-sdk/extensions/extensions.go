package extensions

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	"github.com/genericwsserver/client-sdk/types"
)

type MessageFactory interface {
	CreateMessage(msgType string) (types.ExtendedMessage, error)
	RegisterType(msgType string, example types.ExtendedMessage)
	ParseMessage(data []byte) (types.ExtendedMessage, error)
}

type TypedMessageHandler interface {
	HandleTypedMessage(msgType string, msg types.ExtendedMessage) error
	GetSupportedTypes() []string
}

type MessageRouter struct {
	factory  MessageFactory
	handlers map[string][]TypedMessageHandler
	mu       sync.RWMutex
}

func NewMessageRouter() *MessageRouter {
	return &MessageRouter{
		factory:  NewDefaultMessageFactory(),
		handlers: make(map[string][]TypedMessageHandler),
	}
}

func (mr *MessageRouter) SetFactory(factory MessageFactory) {
	mr.factory = factory
}

func (mr *MessageRouter) RegisterHandler(msgType string, handler TypedMessageHandler) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.handlers[msgType] = append(mr.handlers[msgType], handler)
}

func (mr *MessageRouter) HandleMessage(msg *types.Message) error {
	extMsg, err := mr.factory.ParseMessage([]byte(msg.Body.Content))
	if err != nil {
		return mr.handleBasicMessage(msg)
	}

	extMsg.SetBaseMessage(msg)

	msgType := mr.detectMessageType(extMsg)

	mr.mu.RLock()
	handlers := mr.handlers[msgType]
	mr.mu.RUnlock()

	if len(handlers) == 0 {
		return mr.handleBasicMessage(msg)
	}

	for _, handler := range handlers {
		if err := handler.HandleTypedMessage(msgType, extMsg); err != nil {
			return fmt.Errorf("handler error for type %s: %w", msgType, err)
		}
	}

	return nil
}

func (mr *MessageRouter) handleBasicMessage(msg *types.Message) error {
	mr.mu.RLock()
	handlers := mr.handlers["*"]
	mr.mu.RUnlock()

	for _, handler := range handlers {
		basicExt := &types.BaseExtendedMessage{Message: msg}
		if err := handler.HandleTypedMessage("basic", basicExt); err != nil {
			return err
		}
	}

	return nil
}

func (mr *MessageRouter) detectMessageType(msg types.ExtendedMessage) string {
	t := reflect.TypeOf(msg)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

type DefaultMessageFactory struct {
	types map[string]reflect.Type
	mu    sync.RWMutex
}

func NewDefaultMessageFactory() *DefaultMessageFactory {
	return &DefaultMessageFactory{
		types: make(map[string]reflect.Type),
	}
}

func (dmf *DefaultMessageFactory) RegisterType(msgType string, example types.ExtendedMessage) {
	dmf.mu.Lock()
	defer dmf.mu.Unlock()

	t := reflect.TypeOf(example)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	dmf.types[msgType] = t
}

func (dmf *DefaultMessageFactory) CreateMessage(msgType string) (types.ExtendedMessage, error) {
	dmf.mu.RLock()
	t, exists := dmf.types[msgType]
	dmf.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown message type: %s", msgType)
	}

	msgInterface := reflect.New(t).Interface()
	msg, ok := msgInterface.(types.ExtendedMessage)
	if !ok {
		return nil, fmt.Errorf("registered type does not implement ExtendedMessage interface")
	}

	// Initialize the BaseExtendedMessage if it's nil
	// This ensures SetBaseMessage won't panic
	val := reflect.ValueOf(msg).Elem()
	if baseField := val.FieldByName("BaseExtendedMessage"); baseField.IsValid() {
		if baseField.Kind() == reflect.Ptr && baseField.IsNil() {
			baseField.Set(reflect.New(baseField.Type().Elem()))
			// Also initialize the Message field inside BaseExtendedMessage
			baseMsg := baseField.Elem().FieldByName("Message")
			if baseMsg.IsValid() && baseMsg.Kind() == reflect.Ptr && baseMsg.IsNil() {
				baseMsg.Set(reflect.New(baseMsg.Type().Elem()))
			}
		}
	}

	return msg, nil
}

func (dmf *DefaultMessageFactory) ParseMessage(data []byte) (types.ExtendedMessage, error) {
	var meta struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	if meta.Type == "" {
		return nil, fmt.Errorf("message type not specified")
	}

	msg, err := dmf.CreateMessage(meta.Type)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

type ChainedHandler struct {
	handlers []types.MessageHandler
	mu       sync.RWMutex
}

func NewChainedHandler() *ChainedHandler {
	return &ChainedHandler{
		handlers: make([]types.MessageHandler, 0),
	}
}

func (ch *ChainedHandler) AddHandler(handler types.MessageHandler) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.handlers = append(ch.handlers, handler)
}

func (ch *ChainedHandler) HandleMessage(msg *types.Message) error {
	ch.mu.RLock()
	handlers := make([]types.MessageHandler, len(ch.handlers))
	copy(handlers, ch.handlers)
	ch.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler.HandleMessage(msg); err != nil {
			return err
		}
	}

	return nil
}

type FilteredHandler struct {
	filter  func(*types.Message) bool
	handler types.MessageHandler
}

func NewFilteredHandler(filter func(*types.Message) bool, handler types.MessageHandler) *FilteredHandler {
	return &FilteredHandler{
		filter:  filter,
		handler: handler,
	}
}

func (fh *FilteredHandler) HandleMessage(msg *types.Message) error {
	if fh.filter(msg) {
		return fh.handler.HandleMessage(msg)
	}
	return nil
}

type AsyncHandler struct {
	handler   types.MessageHandler
	queueSize int
	workers   int
	queue     chan *types.Message
	wg        sync.WaitGroup
	ctx       chan struct{}
}

func NewAsyncHandler(handler types.MessageHandler, queueSize, workers int) *AsyncHandler {
	ah := &AsyncHandler{
		handler:   handler,
		queueSize: queueSize,
		workers:   workers,
		queue:     make(chan *types.Message, queueSize),
		ctx:       make(chan struct{}),
	}

	ah.start()
	return ah
}

func (ah *AsyncHandler) start() {
	for i := 0; i < ah.workers; i++ {
		ah.wg.Add(1)
		go ah.worker()
	}
}

func (ah *AsyncHandler) worker() {
	defer ah.wg.Done()

	for {
		select {
		case <-ah.ctx:
			return
		case msg := <-ah.queue:
			if msg != nil {
				ah.handler.HandleMessage(msg)
			}
		}
	}
}

func (ah *AsyncHandler) HandleMessage(msg *types.Message) error {
	select {
	case ah.queue <- msg:
		return nil
	default:
		return fmt.Errorf("async handler queue full")
	}
}

func (ah *AsyncHandler) Stop() {
	close(ah.ctx)
	ah.wg.Wait()
	close(ah.queue)
}
