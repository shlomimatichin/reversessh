all: pep8 pylint

pep8:
	pep8 main.py --max-line-length=119 --ignore=E722

pylint:
	pylint main.py --disable=missing-docstring --disable=R0801,C0103,W0702 --max-line-length=119
#' '--good-names=s3')
