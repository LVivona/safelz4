# Contributing to safelz4

Thank you for your interest in contributing to safelz4! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up the development environment
4. Create a new branch for your changes

## Development Setup

```bash
git clone https://github.com/yourusername/safelz4.git
cd safelz4
python -m pip install -e .
python -m pip install -r requirements-dev.txt
```

```bash
git clone https://github.com/LVivona/safelz4.git
cd safelz4
pip install setuptools_rust
pip install maturin
# install
pip install -e .
# or 
# make develop
```

## Code Guidelines

### Style
- Ignore: E302,E704,E301,F811.
- Use type hints for all public/private functions and methods.
- Maximum line length: 80 characters (Black formatter default).
- Try to use meaningful variable and function names.



To check if your code falls under this style scope just run.
```bash
# check python/rust program
make check
```

You can also just apply them via:
```bash
# run lint format on python/rust
make lint
```

### Documentation
- All public/private functions must have docstrings

Example:
```python
def decompress_prepend_size_with_dict(input: bytes, ext_dict: bytes) -> bytes:
    """
    Decompress input bytes using a user-provided dictionary of bytes, size is already pre-appended.
    Args:
        input (`bytes`):
            fixed set of bytes to be decompressed.
        ext_dict (`bytes`):
            Dictionary used for decompression.

    Returns:
        (`bytes`): decompressed data.
    """
    ...
```

### Testing
- Write tests for all new functionality
- Run the full test suite before submitting

```bash
make test
```

## Submitting Changes

### Pull Request Process

1. Create a feature branch from `main` call it `feature/<name>/<feature>`
2. **Try** to make your changes in logical, atomic commits
3. Write clear commit messages
4. Push to your fork and submit a pull request.

### Commit Messages
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Example:
```
fix: compression ratio calculation for small files

The ratio was incorrectly calculated when input size was less than
block size, causing division by zero errors.

Fixes #123
```

### Pull Request Guidelines
- Include a clear description of the problem and solution
- Include relevant issue numbers
- Add tests for new functionality
- Update documentation as needed
- Ensure CI passes

## Code Review

All submissions require review. We use GitHub pull requests for this purpose. Reviewers will check for:

- Code quality and style
- Test coverage
- Documentation completeness
- Performance implications
- Security considerations

## Types of Contributions

### Bug Reports
- Include minimal reproduction case
- Specify environment details (OS, Python version, etc.)
- Include relevant error messages and stack traces

### Feature Requests
- Describe the use case
- Explain why the feature would be useful
- Consider implementation complexity
- Be open to alternative solutions

### Code Contributions
- Bug fixes
- Performance improvements
- New features
- Documentation improvements
- Test improvements

## Performance Considerations

safelz4 is a performance-critical library. When contributing:

- Benchmark your changes
- Consider memory usage implications
- Profile critical paths
- Document performance characteristics
- Include performance tests for significant changes

## Questions?

- Open an issue for bug reports or feature requests
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.