# -*- coding: utf-8 -*-

# This is based on build_manpage originally downloaded from:
# https://github.com/pwman3/pwman3/

# Original license:
# This file is distributed under the same License of Python
# Copyright (c) 2014 Oz Nahum Tiram  <nahumoz@gmail.com>

import datetime
from distutils.core import Command
from distutils.errors import DistutilsOptionError
from distutils.command.build import build
import argparse
import re

def build_manpage(parser, output, appname, description, long_description, authors, homepage, pre_sections=[]):
    argparser = parser(formatter_class=ManPageFormatter)
    sections = {'authors': authors,
                'distribution': ("The latest version of {} may be "
                                 "downloaded from {}".format(appname,
                                                             homepage))
                }

    mpf = ManPageFormatter(appname,
                           desc=description,
                           pre_sections=pre_sections,
                           long_desc=long_description,
                           ext_sections=sections)

    m = mpf.format_man_page(argparser)

    with open(output, 'w') as f:
        f.write(m)


class ManPageFormatter(argparse.HelpFormatter):
    """
    Formatter class to create man pages.
    This class relies only on the parser, and not distutils.
    The following shows a scenario for usage::

        from pwman import parser_options
        from build_manpage import ManPageFormatter

        # example usage ...

        dist = distribution
        mpf = ManPageFormatter(appname,
                               desc=dist.get_description(),
                               long_desc=dist.get_long_description(),
                               ext_sections=sections)

        # parser is an ArgumentParser instance
        m = mpf.format_man_page(parsr)

        with open(self.output, 'w') as f:
            f.write(m)

    The last line would print all the options and help infomation wrapped with
    man page macros where needed.
    """

    def __init__(self,
                 prog,
                 indent_increment=2,
                 max_help_position=24,
                 width=None,
                 section=1,
                 desc=None,
                 long_desc=None,
                 pre_sections=[],
                 ext_sections=None,
                 authors=None,
                 ):

        super(ManPageFormatter, self).__init__(prog)

        self._prog = prog
        self._section = 1
        self._today = datetime.date.today().strftime('%Y\\-%m\\-%d')
        self._desc = desc
        self._long_desc = long_desc
        self._pre_sections = pre_sections
        self._ext_sections = ext_sections

    def _get_formatter(self, **kwargs):
        return self.formatter_class(prog=self.prog, **kwargs)

    def _markup(self, txt):
        return txt.replace('-', '\\-')

    def _underline(self, string):
        return "\\fI\\s-1" + string + "\\s0\\fR"

    def _bold(self, string):
        if not string.strip().startswith('\\fB'):
            string = '\\fB' + string
        if not string.strip().endswith('\\fR'):
            string = string + '\\fR'
        return string

    def _mk_synopsis(self, parser):
        self.add_usage(parser.usage, parser._actions,
                       parser._mutually_exclusive_groups, prefix='')
        usage = self._format_usage(None, parser._actions,
                                   parser._mutually_exclusive_groups, '')

        usage = usage.replace('%s ' % self._prog, '')
        usage = '.SH SYNOPSIS\n \\fB%s\\fR %s\n' % (self._markup(self._prog),
                                                    usage)
        return usage

    def _mk_title(self, prog):
        return '.TH {0} {1} {2}\n'.format(prog, self._section,
                                          self._today)

    def _make_name(self, parser):
        """
        this method is in consitent with others ... it relies on
        distribution
        """
        return '.SH NAME\n%s \\- %s\n' % (parser.prog,
                                          parser.description)

    def _mk_description(self):
        if self._long_desc:
            long_desc = self._long_desc.replace('\n', '\n.br\n')
            return '.SH DESCRIPTION\n%s\n' % self._markup(long_desc)
        else:
            return ''

    def _mk_section(self, name, content):
        content = content.replace('\n', '\n.br\n')
        content = re.sub(r"`(.*)` ", r"\\fB\\fC\1\\fR\n", content)
        return '.SH %s\n%s\n' % (name.upper(), self._markup(content))

    def _mk_footer(self, sections):
        if not hasattr(sections, '__iter__'):
            return ''

        footer = []
        for section, value in sections.items():
            part = ".SH {}\n {}".format(section.upper(), value)
            footer.append(part)

        return '\n'.join(footer)

    def format_man_page(self, parser):
        page = []
        page.append(self._mk_title(self._prog))
        page.append(self._mk_synopsis(parser))
        page.append(self._mk_description())
        for name, content in self._pre_sections:
            page.append(self._mk_section(name, content))
        #page.append(self._mk_options(parser))
        page.append(self._mk_footer(self._ext_sections))

        return ''.join(page)

    def _mk_options(self, parser):

        formatter = parser._get_formatter()

        # positionals, optionals and user-defined groups
        for action_group in parser._action_groups:
            formatter.start_section(None)
            formatter.add_text(None)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()

        # epilog
        formatter.add_text(parser.epilog)

        # determine help from format above
        return '.SH OPTIONS\n' + formatter.format_help()

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar

        else:
            parts = []

            # if the Optional doesn't take a value, format is:
            #    -s, --long
            if action.nargs == 0:
                parts.extend([self._bold(action_str) for action_str in action.option_strings])

            # if the Optional takes a value, format is:
            #    -s ARGS, --long ARGS
            else:
                default = self._underline(action.dest.upper())
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append('%s %s' % (self._bold(option_string), args_string))

            return ', '.join(parts)


if __name__ == "__main__":
    build_manpage()
