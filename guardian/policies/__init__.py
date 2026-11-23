"""Editable policy data (rule weights, end-of-life dates) shipped as package data."""
import json
from importlib import resources


def load(name):
    data = json.loads(resources.files(__package__).joinpath(name).read_text())
    return {k: v for k, v in data.items() if not k.startswith("_")}
