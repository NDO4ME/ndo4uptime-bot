.PHONY: build run test lint fmt docker up down clean help

APP_NAME := ndo4uptime
IMAGE    := ghcr.io/ndo4me/ndo4uptime-bot

## build: Build the optimized release binary
build:
	cargo build --release --locked

## run: Run locally (data in ./data, http://127.0.0.1:8589)
run:
	NDO4_DATA=./data cargo run

## test: Run unit tests
test:
	cargo test --locked

## lint: Check formatting and run clippy with warnings as errors
lint:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings

## fmt: Format Rust code
fmt:
	cargo fmt

## docker: Build the Docker image locally
docker:
	docker build -t $(IMAGE):local .

## up: Build and start with Docker Compose
up:
	docker compose up -d --build

## down: Stop the Compose stack (data volume is kept)
down:
	docker compose down

## clean: Remove build artifacts
clean:
	cargo clean
	rm -rf data

## help: List targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
