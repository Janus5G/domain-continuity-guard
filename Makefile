.PHONY: install lint test cs package

install:
	composer install

lint:
	composer lint

test:
	composer test

cs:
	composer cs

package:
	mkdir -p dist
	zip -r dist/domain-continuity-guard.zip . -x "vendor/*" ".git/*" "dist/*"
