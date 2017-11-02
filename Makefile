ACCOUNT=foxdalas
APP_NAME=kube-cfssl

PACKAGE_NAME=github.com/${ACCOUNT}/${APP_NAME}
GO_VERSION=1.9.1

GOOS := linux
GOARCH := amd64

DOCKER_IMAGE=${ACCOUNT}/${APP_NAME}

BUILD_DIR=_build
TEST_DIR=_test

CONTAINER_DIR=/go/src/${PACKAGE_NAME}

BUILD_TAG := build
IMAGE_TAGS := canary

PACKAGES=$(shell find . -name "*_test.go" | xargs -n1 dirname | grep -v 'vendor/' | sort -u | xargs -n1 printf "%s.test_pkg ")

.PHONY: version

all: test build

depend:
	rm -rf $(TEST_DIR)/
	rm -rf ${BUILD_DIR}/
	mkdir $(TEST_DIR)/
	mkdir $(BUILD_DIR)/

version:
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo "clean"; else echo "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))
	$(eval APP_VERSION ?= $(shell cat VERSION))
	@echo $(APP_VERSION)

%.test_pkg: test_prepare
	$(eval PKG := ./$*)
	$(eval PKG_CLEAN := $(shell echo "$*" | sed "s#^p#.p#" | sed "s#/#-#g"))
	@echo "test $(PKG_CLEAN) ($(PKG))"
	bash -o pipefail -c "go test -v -coverprofile=$(TEST_DIR)/coverage$(PKG_CLEAN).txt -covermode count $(PKG) | tee $(TEST_DIR)/test$(PKG_CLEAN).out"
	cat $(TEST_DIR)/test$(PKG_CLEAN).out | go2xunit > $(TEST_DIR)/test$(PKG_CLEAN).xml
	gocover-cobertura < $(TEST_DIR)/coverage$(PKG_CLEAN).txt > $(TEST_DIR)/coverage$(PKG_CLEAN).xml

build: depend version
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a -tags netgo \
		-o ${BUILD_DIR}/${APP_NAME}-$(GOOS)-$(GOARCH) \
		-ldflags "-X main.AppGitState=${GIT_STATE} -X main.AppGitCommit=${GIT_COMMIT} -X main.AppVersion=${APP_VERSION}"

docker: 

image: version
	docker build --build-arg VCS_REF=$(GIT_COMMIT) -t $(DOCKER_IMAGE):$(BUILD_TAG) .
	
push: image
	set -e; \
	for tag in $(IMAGE_TAGS); do \
		docker tag  $(DOCKER_IMAGE):$(BUILD_TAG) $(DOCKER_IMAGE):$${tag} ; \
		docker push $(DOCKER_IMAGE):$${tag}; \
	done
