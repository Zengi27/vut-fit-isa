CC=gcc

TARGET=client

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)