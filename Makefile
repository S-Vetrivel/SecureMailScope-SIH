.PHONY: dev backend frontend build test run clean lab-up lab-down

# Run backend only
backend:
	@echo "Starting Go backend on :8080..."
	@cd backend && go run ./cmd/server

# Run frontend only
frontend:
	@echo "Starting Vite dashboard on :3000..."
	@cd dashboard && npm run dev

# Kill any processes using the dev ports, then start both
dev:
	@echo "Freeing ports 8080 and 3000..."
	@-fuser -k 8080/tcp 2>/dev/null; true
	@-fuser -k 3000/tcp 2>/dev/null; true
	@sleep 1
	@echo "Starting backend (background) and dashboard (foreground)..."
	@cd backend && go run ./cmd/server &
	@sleep 2
	@cd dashboard && npm run dev

build:
	@echo "Building Go backend..."
	@cd backend && CGO_ENABLED=0 go build -o ../bin/server ./cmd/server

test:
	@echo "Running backend unit tests..."
	@cd backend && go test -v ./...

run: build
	@echo "Running backend server on :8080..."
	@-fuser -k 8080/tcp 2>/dev/null; true
	@./bin/server

clean:
	@echo "Cleaning build artifacts and freeing ports..."
	@-fuser -k 8080/tcp 2>/dev/null; true
	@-fuser -k 3000/tcp 2>/dev/null; true
	@-rm -f bin/server

lab-up:
	@echo "Starting docker-compose environment..."
	@cd lab && docker-compose up -d

lab-down:
	@echo "Stopping docker-compose environment..."
	@cd lab && docker-compose down
