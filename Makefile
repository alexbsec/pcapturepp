# Variables
BUILD_DIR = build
CMAKE = cmake
MAKE = make

# Default target
all: build_dir
	@$(CMAKE) -S . -B $(BUILD_DIR)
	@$(MAKE) -C $(BUILD_DIR)
# Create build directory if it doesn't exist
build_dir:
	@mkdir -p $(BUILD_DIR)

# Run tests
test: all
	@$(BUILD_DIR)/runTests

# Clean build directory
clean:
	@rm -rf $(BUILD_DIR)

# Rebuild project
rebuild: clean all
