import nox


@nox.session(python=["python3.11"])
def build(session: nox.Session) -> None:
    """Build the dist."""
    session.install("-r", "requirements.txt")
    session.install("requests")
    session.install("build")
    session.install("pynacl")
    session.env["PYTHONPATH"] = "basicnanoclient"
    session.run("python", "-m", "build")

    # publish pip package
    session.install("twine")
    session.run("twine", "upload", "dist/*")


@nox.session(python=["python3.11"])
def tests(session: nox.Session) -> None:
    """Run the tests."""
    session.install("-r", "requirements.txt")
    session.install('pytest')
    session.install("pytest-cov")
    session.env["PYTHONPATH"] = "basicnanoclient"
    session.run("pytest", "--cov=basicnanoclient", "--cov-fail-under=80")


@nox.session(python=["python3.11"])
def lint(session: nox.Session) -> None:
    """Run the linter checks."""
    session.install('flake8')
    session.install("-r", "requirements.txt")

    # lint the source code
    session.run(
        'flake8', 'basicnanoclient',
        '--docstring-convention', 'google',
        '--ignore=D100'
    )

    # lint the tests
    session.run(
        'flake8', 'tests',
        '--docstring-convention', 'google',
        '--ignore=D100,D104'
    )
