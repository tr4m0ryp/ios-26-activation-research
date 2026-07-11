NAME = $(notdir $(CURDIR))

poc: poc.m
	clang -framework Foundation -fobjc-arc -Wall -Wextra -o poc poc.m

run: poc
	@mkdir -p logs
	./poc 2>&1 | tee logs/$(shell date +%Y-%m-%d_%H%M%S)_run.log

zip:
	@cd .. && zip -r $(NAME).zip $(NAME)/ && echo "Created ../$(NAME).zip"

clean:
	rm -f poc

.PHONY: run zip clean
