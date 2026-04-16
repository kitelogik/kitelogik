.PHONY: stop clean test demo landing

stop:
	@docker compose stop 2>/dev/null || true
	@echo "containers stopped"

# Remove all local SQLite databases — resets dev state to a blank slate.
clean: stop
	@rm -f hitl.db memory.db events.db credentials.db dev/*.db
	@echo "local databases removed — next start will begin with empty state"

# Demo — run governance quickstart (requires OPA: docker compose up -d opa).
demo:
	python quickstart.py

# Landing page dev server with live reload.
landing:
	@pip install livereload -q
	@echo "  Landing page → http://localhost:8099/landing.html"
	@echo "  Edit docs/landing.html — browser reloads on save. Ctrl-C to stop."
	@python scripts/landing_dev.py

test:
	pytest -q
