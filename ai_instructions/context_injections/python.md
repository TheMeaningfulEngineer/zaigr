Always check code through ruff all ruff tests have to pass.
Use type annotations and check the codebase with mypy.

Each function must have a docstring describing the function:
Good example:

```python
def connect_to_next_port(minimum: int) -> int:
  """Connects to the next available port.

  Args:
    minimum: A port value greater or equal to 1024.

  Returns:
    The new minimum port.

  Raises:
    ConnectionError: If no available port is found.
"""
```

Once you write the function always reread the docstring and ask yourself:
Could I have renamed the artuments and function better so that the docstring is shorter?
Is the docstring to big and this should be multiple functions?

Don't do that for the main function.


When in doubt wether to optimise for readability or performance, choose readability.

Use standard python logging.
