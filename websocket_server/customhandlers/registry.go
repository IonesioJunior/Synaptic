package customhandlers

import (
	"log"
	"sync"

	"websocketserver/ws"
)

type HandlerFactory func() ws.ServerMessageHandler

type HandlerRegistration struct {
	Command     string
	Factory     HandlerFactory
	Description string
}

var (
	registry = make([]HandlerRegistration, 0)
	mu       sync.Mutex
)

func Register(command string, factory HandlerFactory, description string) {
	mu.Lock()
	defer mu.Unlock()

	registry = append(registry, HandlerRegistration{
		Command:     command,
		Factory:     factory,
		Description: description,
	})

	log.Printf("Custom handler registered: %s - %s", command, description)
}

func RegisterAll(server *ws.Server) error {
	mu.Lock()
	defer mu.Unlock()

	for _, reg := range registry {
		handler := reg.Factory()
		if err := server.RegisterServerHandler(reg.Command, handler); err != nil {
			log.Printf("Failed to register custom handler '%s': %v", reg.Command, err)
			return err
		}
		log.Printf("Successfully registered custom handler: %s", reg.Command)
	}

	log.Printf("Registered %d custom handlers", len(registry))
	return nil
}

func GetRegisteredHandlers() []HandlerRegistration {
	mu.Lock()
	defer mu.Unlock()

	result := make([]HandlerRegistration, len(registry))
	copy(result, registry)
	return result
}
