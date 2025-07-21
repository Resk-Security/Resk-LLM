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
copyright = '2025, Resk'
author = 'Resk'

# The full version, including alpha/beta/rc tags
# Try to get the version from the package itself
try:
    from resk_llm import __version__ as release
except ImportError:
    release = '0.5.0' # Fallback version

version = release

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
    'sphinx.ext.todo',
    'myst_parser',
    'autoapi.extension',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', '**/tests/**', '**/migrations/**']

# The suffix of source filenames.
source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
}

# Tell myst-parser to auto-generate anchor links for headers H1 to H3
myst_heading_anchors = 3

# AutoAPI configuration
autoapi_dirs = ['../resk_llm']  # Location of the source code
autoapi_root = 'autoapi'
autoapi_options = [
    'members', 
    'undoc-members',
    'show-inheritance', 
    'show-module-summary', 
    'special-members',
    'imported-members',
]
autoapi_ignore = ['*migrations*', '*/tests/*', '*/__pycache__/*']
autoapi_keep_files = False
autoapi_add_toctree_entry = True
autoapi_type_aliases = {
    'Dict': 'Dict',
    'List': 'List',
    'Tuple': 'Tuple',
    'Optional': 'Optional',
    'Union': 'Union',
    'Any': 'Any',
}

# Napoleon settings for Google-style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = True
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Theme options
html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
    'github_url': 'https://github.com/your-username/resk-llm',  # Update with your repo
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': True,
    'style_nav_header_background': '#2980B9',
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".

# Intersphinx configuration
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'sphinx': ('https://www.sphinx-doc.org/en/master/', None),
}

# -- Options for PDF output --------------------------------------------------
latex_elements = {
    'papersize': 'a4paper',
    'pointsize': '11pt',
    'figure_align': 'htbp',
}

# -- Options for EPUB output -------------------------------------------------
epub_show_urls = 'footnote'

# -- Extension configuration -------------------------------------------------
todo_include_todos = True

# -- ReadTheDocs specific configuration --------------------------------------
# On ReadTheDocs, we need to install the package in editable mode
if os.environ.get('READTHEDOCS') == 'True':
    # Install the package in editable mode
    import subprocess
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-e', '..'], check=True) 