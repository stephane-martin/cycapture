# -*- coding: utf-8 -*-

import sys
import os
import shutil
from os.path import join, dirname, abspath, exists
import logging

os.environ['SPHINX_BUILD'] = "True"
on_rtd = os.environ.get('READTHEDOCS', None) == 'True'

if not on_rtd:
    try:
        import cycapture.libpcap
        import cycapture.libtins
    except ImportError:
        sys.path.insert(0, os.path.abspath('..'))
        import cycapture.libpcap
        import cycapture.libtins
else:
    # we are on readthedocs...
    print("Im on readthedocs")

project = u'cycapture'
copyright = u'2015, Stephane Martin'
author = u'Stephane Martin'
version = '0.2'
release = '0.2'

html_theme_path = [abspath(join(dirname(__file__), 'theme'))]
html_theme = 'cycapture'
html_theme_options = {}
html_title = "cycapture documentation"
html_short_title = "cycapture"
htmlhelp_basename = 'cycapturedoc'
html_extra_path = []
if on_rtd:
    # on RTD, we just overwrite the built documentation with the content of static_build :)
    print("RTD: configuring html_extra_path")
    html_extra_path.append('static_build/html')

extensions = [
    'sphinx.ext.autodoc', 'sphinx.ext.napoleon', 'sphinx.ext.viewcode', 'sphinx.ext.graphviz'
]

graphviz_output_format = "svg"
autoclass_content = 'both'
autodoc_member_order = 'groupwise'
autodoc_default_flags = ['members', 'show-inheritance']
napoleon_include_private_with_doc = True
napoleon_include_special_with_doc = False
napoleon_use_ivar = False
napoleon_use_param = False
napoleon_use_rtype = False
autodoc_docstring_signature = True
autodoc_mock_imports = []

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
language = None
exclude_patterns = ['_build', 'static_build']
add_function_parentheses = True
add_module_names = False
show_authors = False
pygments_style = 'sphinx'
keep_warnings = False
todo_include_todos = False
html_use_smartypants = False
html_static_path = ['_static']
html_sidebars = {'**': ['mytoc.html']}
html_domain_indices = True
html_use_index = True
html_split_index = False
html_show_sourcelink = False
html_show_sphinx = False
html_theme_show_powered_by = False
html_show_copyright = False
html_search_language = 'en'
#html_logo = None
#html_favicon = None

# Additional templates that should be rendered to pages, maps page names to template names.
# html_additional_pages = {
#     'index': 'customdownload.html',
# }





