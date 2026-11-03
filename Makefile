.PHONY: check build
check:
	python3 -m unittest discover -s tests -v
	bash -n deploy/build.sh deploy/bootstrap.sh deploy/apply-release.sh deploy/ci-deploy.sh
build:
	bash deploy/build.sh
