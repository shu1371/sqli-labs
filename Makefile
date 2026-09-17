.PHONY: build run stop clean test log

# 变量
IMAGE_NAME ?= sqli-labs
CONTAINER_NAME ?= sqli-labs
PORT ?= 8000

build:
	docker build -t $(IMAGE_NAME):latest .

up:
	docker run -d --name $(CONTAINER_NAME) -p $(PORT):8000 \
		-e FLAG=FLAG{moxiang_bookstore_pwned} \
		--restart unless-stopped \
		$(IMAGE_NAME):latest

down:
	docker stop $(CONTAINER_NAME) 2>/dev/null || true
	docker rm $(CONTAINER_NAME) 2>/dev/null || true

restart: down up

logs:
	docker logs -f $(CONTAINER_NAME)

clean:
	docker rmi -f $(IMAGE_NAME):latest 2>/dev/null || true

# 开发调试
dev:
	python app.py

test:
	python -m pytest tests/ -v
