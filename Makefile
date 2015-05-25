CURRENT=$(shell date +%Y%m%d)

all: version

version:
	@echo "Generating ${CURRENT}"
	@echo "package main\nconst npVersion string = \"`date +%Y%m%d`\"\n" > version.go

