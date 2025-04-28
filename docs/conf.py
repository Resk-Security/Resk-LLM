# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
# Point to the project root to find the package
sys.path.insert(0, os.path.abspath('../'))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'resk-llm'
copyright = '2024, Resk'
author = 'Resk'
# The full version, including alpha/beta/rc tags
# Try to get the version from the package itself
try:
    from resk_llm import __version__ as release
except ImportError:
    release = '0.5.0' # Fallback version

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx.ext.viewcode',
    'myst_parser',
    'autoapi.extension',  # Only this, not 'sphinx_autoapi.extension'
]


templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# Tell myst-parser to auto-generate anchor links for headers H1 to H3
myst_heading_anchors = 3

# AutoAPI configuration
autoapi_dirs = ['../resk_llm'] # Location of the source code
autoapi_root = 'autoapi'
autoapi_options = [
    'members', 
    'undoc-members',
    # 'private-members',
    'show-inheritance', 
    'show-module-summary', 
    'special-members',
    # 'imported-members',
]
autoapi_ignore = ['*migrations*', '*/tests/*']
autoapi_keep_files = False
autoapi_add_toctree_entry = True

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".

# Intersphinx configuration
# Example configuration for linking to the Python documentation
intersphinx_mapping = {'python': ('https://docs.python.org/3', None)} 