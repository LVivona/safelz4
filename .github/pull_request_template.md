## 📋 Description

Provide a concise and clear summary of the changes introduced in this pull request.  
Please include:
- The motivation for the change
- A brief explanation of the implementation
- Any relevant technical notes

Example:
> This PR adds Python bindings to the `compute_loss` function using PyO3. It also introduces unit tests on the Python side to validate the Rust logic.

---

## 🧩 Related Issues

Link to any existing issues that this PR resolves or relates to.  
Use keywords like `Closes`, `Fixes`, or `See also`.

Example:
> Closes #42  
> See also: #40, #41

If there are **no related issues**, write `NRI`.

---

## 🧪 Testing

Describe how the changes were tested. Include:
- Commands used (`cargo test`, `pytest`, etc.)
- Platforms tested (Linux, macOS, Windows)
- Any CI results (if applicable)

Example:
> - Ran `maturin develop` and executed tests via `pytest tests/`  
> - Verified with `cargo test` on Rust 1.x

---

## 🔗 Python API Changes (if applicable)

If the PR adds or modifies any Python bindings, document the new or updated interfaces.

Example:
```python
# Before
def compute_loss(input: List[float]) -> float: ...

# After
def compute_loss(input: List[float], normalize: bool = False) -> float: ...
