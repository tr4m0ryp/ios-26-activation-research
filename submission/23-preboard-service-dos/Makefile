CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS =
NAME    = $(notdir $(CURDIR))

ifneq ($(shell pkg-config --exists libimobiledevice-1.0 2>/dev/null && echo y),)
  CFLAGS  += $(shell pkg-config --cflags libimobiledevice-1.0)
  LDFLAGS += $(shell pkg-config --libs   libimobiledevice-1.0)
else
  CFLAGS  += -I/opt/homebrew/include/libimobiledevice-1.0
  LDFLAGS += -L/opt/homebrew/lib -limobiledevice-1.0
endif

ifneq ($(shell pkg-config --exists libplist-2.0 2>/dev/null && echo y),)
  CFLAGS  += $(shell pkg-config --cflags libplist-2.0)
  LDFLAGS += $(shell pkg-config --libs   libplist-2.0)
else
  CFLAGS  += -I/opt/homebrew/include/libplist-2.0
  LDFLAGS += -L/opt/homebrew/lib -lplist-2.0
endif

poc: poc.c
	$(CC) $(CFLAGS) -o poc poc.c $(LDFLAGS)

run: poc
	@mkdir -p logs
	./poc 2>&1 | tee logs/$(shell date +%Y-%m-%d_%H%M%S)_run.log

zip:
	@cd .. && zip -r $(NAME).zip $(NAME)/ && echo "Created ../$(NAME).zip"

clean:
	rm -f poc

.PHONY: run zip clean
