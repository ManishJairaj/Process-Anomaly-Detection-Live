CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

TARGET = syscall-detector

SRC = src/main.c src/event.c src/ngram.c src/window.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
