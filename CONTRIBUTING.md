# Contributing to QuorumTrust

Thank you for your interest in contributing to QuorumTrust! This document provides guidelines and instructions for contributing.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Exercise consideration and empathy in your speech and actions
- Refrain from demeaning, discriminatory, or harassing behavior

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:
- A clear and descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment details (OS, Rust version, etc.)
- Relevant logs or screenshots

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:
- A clear use case description
- Expected behavior
- Potential implementation approach (if any)

### Your First Code Contribution

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and lints (`make test lint fmt`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

### Prerequisites
- Rust (edition 2021 or later)
- cargo, rustfmt, clippy
- Optional: Docker for containerized development

### Quick Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/QuorumTrust.git
cd QuorumTrust

# Add upstream
git remote add upstream https://github.com/jose-compu/QuorumTrust.git

# Install development tools
make setup

# Build the project
make build

# Run tests
make test
```

### IDE Setup

**VS Code:**
- Install `rust-analyzer` extension
- Install `Even Better TOML` for Cargo.toml support

**IntelliJ/CLion:**
- Install `Rust` plugin
- Enable clippy inspections

## Coding Standards

### Rust Style
- Follow standard Rust conventions
- Use `rustfmt` for formatting (config in `rustfmt.toml`)
- Use `clippy` for linting (config in `clippy.toml`)
- Run `make fmt lint` before committing

### Commit Messages

Follow Conventional Commits:
```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(crypto): add key rotation mechanism`
- `fix(network): resolve gossip retry logic`
- `docs: update API documentation`

### Documentation
- Add inline documentation for public APIs
- Use `///` for function documentation
- Use `//` for implementation comments
- Run `make docs` to generate documentation

## Pull Request Process

1. **Ensure your PR**:
   - Targets `main` branch
   - Has a clear title and description
   - Links to relevant issues (e.g., "Closes #123")
   - Passes all CI checks
   - Has no merge conflicts

2. **PR Description Template**:
   ```markdown
   ## Description
   Brief description of changes.

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Added unit tests
   - [ ] Added integration tests
   - [ ] All tests pass

   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] No new warnings
   ```

3. **Review Process**:
   - At least one maintainer approval required
   - Address feedback promptly
   - Keep PR up-to-date with `main`

## Community

- **Issues**: Bug reports, feature requests, discussions
- **Discussions**: General questions, ideas, community chat
- **Security**: Report security vulnerabilities to jose.comp2@gmail.com

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

---

Thank you for contributing to QuorumTrust! 🚀
