# web_support.py -- simple HTTP generation framework
# Copyright (C) 2005 Florian Weimer <fw@deneb.enyo.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

import cgi
import os
import re
import socket
import struct
import sys
import grp
import traceback
import threading

try:
    from urllib import quote as urllib_quote
except ImportError:
    from urllib.parse import quote as urllib_quote

try:
    from cgi import parse_qs
except ImportError:
    from urllib.parse import parse_qs

try:
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from socketserver import ThreadingMixIn
    from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

from helpers import isstring

class ServinvokeError(Exception):
    pass

class Service:
    """A class for service objects.

    Service objects are contacted by the program servinvoke and
    process HTTP requests in a serialized fashion.  (Only the data
    transfer from and to the client happens in parallel, and this is
    handled by the servinvoke program.)

    If the newly created socket is owned by the www-data group, it is
    automatically made readable by that group.
    """

    def __init__(self, socket_name):
        self.socket_name = socket_name
        self._unlinkSocket()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        self.socket.bind(self.socket_name)
        self.socket.listen(5)
        self._chmod()

    def __del__(self):
        self._unlinkSocket()

    def _unlinkSocket(self):
        try:
            os.unlink(self.socket_name)
        except OSError:
            pass

    def _chmod(self):
        gid = os.stat(self.socket_name).st_gid
        grpent = grp.getgrgid(gid)
        if grpent[0] == 'www-data':
            os.chmod(self.socket_name, 0o660)

    def log(self, msg, *args):
        sys.stderr.write((msg % args) + "\n")

    def run(self):
        while 1:
            (client, addr) = self.socket.accept()

            def read(count):
                data = ''
                cnt = 0
                while cnt != count:
                    d = client.recv(count - cnt)
                    if d:
                        data += d
                        cnt = len(data)
                    else:
                        self.log("unexpected end of data from servinvoke")
                        raise ServinvokeError()

                return data

            try:
                header = read(24)
                (magic, version, cli_size, cli_count, env_size, env_count) = \
                        struct.unpack("!6I", header)
                if magic != 0x15fd34df:
                    sys.log("unknown magic number %08X", magic)
                if version != 1:
                    sys.log("unknown version %08X", magic)
                cli = read(cli_size).split('\0')[:-1]
                env = {}
                for x in read(env_size).split('\0')[:-1]:
                    (key, value) = x.split('=', 1)
                    env[key] = value
                data = []
                while 1:
                    d = client.recv(4096)
                    if d:
                        data.append(d)
                    else:
                        break
                data = ''.join(data)
                result = StringIO()
                self.handle(cli, env, data, result)
                client.sendall(result.getvalue())
                client.close()

            except ServinvokeError:
                client.close()
                pass
            except KeyboardInterrupt:
                client.close()
                raise
            except:
                client.close()
                target = StringIO()
                traceback.print_exc(None, target)
                self.log("%s", target.getvalue())

        def handle(args, environ, data):
            """Invoke by run to handle a single request.  Should
            return the data to be sent back to the client."""
            return ""

class URL:
    """A simple wrapper class for strings which are interpreted as URLs."""
    def __init__(self, url):
        self.__url = url
    def __str__(self):
        return self.__url
    def __repr__(self):
        return "URL(%s)" % repr(self.__url)

class URLFactory:
    """Creates URL objects.

    This factory class handles the case where a script wants to
    generate URLs which reference to itself (see scriptRelative)."""

    def __init__(self, server_name, script_name, path_info='',
                 params={}, secure=False):
        self.server_name = server_name or 'localhost'
        script_name = self._stripSlashes(script_name or '')
        if script_name[-1:] == '/' or script_name == '':
            self.script_name = script_name
        else:
            self.script_name = script_name + '/'
        self.path_info = self._stripSlashes(path_info)
        self.params = params
        self.secure = secure

    def _convertArgs(self, args):
        arglist = []
        for (key, value) in args.items():
            if value is None:
                continue
            if not isinstance(value, (list, tuple)):
                value = (value,)
            for v in value:
                arglist.append("%s=%s" % (urllib_quote(key),
                                          urllib_quote(v)))
        if arglist:
            return "?" + '&'.join(arglist)
        else:
            return ""
    def _stripSlashes(self, arg):
        while arg[:1] == '/':
            arg = arg[1:]
        return arg

    def absolute(self, url, **args):
        """Creates an absolute URL, with optional arguments to pass."""

        return URL(url + self._convertArgs(args))

    def absoluteDict(self, url, args):
        """Creates an absolute URL, with arguments to pass."""

        return URL(url + self._convertArgs(args))

    def scriptRelative(self, path, **args):
        """Returns a URL which references to the path relative to the
        current script.  Optionally, arguments to pass can be included."""

        return URL("/%s%s%s" % (self.script_name,
                                self._stripSlashes(path),
                                self._convertArgs(args)))

    def scriptRelativeFull(self, path, **args):
        """Like scriptRelative, but returns an absolute URL, including
        the http:// prefix."""
        if self.secure:
            schema = "https"
        else:
            schema = "http"
        return URL("%s://%s/%s%s%s" % (schema,
                                       self.server_name, self.script_name,
                                       self._stripSlashes(path),
                                       self._convertArgs(args)))

    def updateParamsDict(self, args):
        new_args = {}
        for (key, value) in self.params.items():
            new_args[key] = value
        for (key, value) in args.items():
            new_args[key] = value
        return URL("/%s%s%s" % (self.script_name, self.path_info,
                                self._convertArgs(new_args)))

    def updateParams(self, **args):
        self.updateParamsDict(args)

charToHTML = {
    '<' : '&lt;',
    '>' : '&gt;',
    '&' : '&amp;',
}
charToHTMLattr = {
    '&' : '&amp;',
    '"' : '&34;',
}

def escapeHTML(str):
    '''Replaces the characters <>& in the passed strings with their
    HTML entities.'''
    return ''.join([charToHTML.get(ch, ch) for ch in str])

def escapeHTMLattr(str):
    '''Replaces the characters &" in the passed strings with their
    HTML entities.'''
    return ''.join([charToHTMLattr.get(ch, ch) for ch in str])

class HTMLBase:
    def flatten(self, write):
        """Invokes write repeatedly, for the tag and its contents.

        Note that typically, a lot of very short strings a written, so
        it's better to add some buffering before sending the strings
        elsewhere."""
        pass

    def toString(self):
        """Invokes flatten to create a new string object."""
        r = StringIO()
        self.flatten(r.write)
        return r.getvalue()

    def toHTML(self):
        return VerbatimHTML(self.toString())

class VerbatimHTML(HTMLBase):
    """Creates verbatim HTML from a string object.  Mainly used for
    optimizing recurring HTML snippets."""

    def __init__(self, contents):
        self.__contents = contents

    def flatten(self, write):
        write(self.__contents)

class Compose(HTMLBase):
    """Glues a sequence of HTML snippets together, without enclosing it in
    a tag."""
    def __init__(self, contents):
        self.__contents = contents

    def flatten(self, write):
        for x in self.__contents:
            if isstring(x):
                write(escapeHTML(x))
            else:
                x.flatten(write)

def compose(*contents):
    """Concatenates several HTML objects."""
    return Compose(contents)


class Tag(HTMLBase):
    """Base class for HTML tags."""

    re_name = re.compile(r'\A_?[a-zA-Z][a-zA-Z0-9]*\Z')

    def __init__(self, name, contents, attribs={}):
        self._check(name)
        self.__name = name
        attrs = []
        append = attrs.append
        for (key, value) in attribs.items():
            if value is None:
                continue
            self._check(key)
            append(' ')
            if key[0] == '_':
                append(key[1:])
            else:
                append(key)
            append('="')
            append(escapeHTMLattr(str(value)))
            append('"')
        self.__attribs = ''.join(attrs)
        self.contents = contents

    def _check(self, name):
        if self.re_name.match(name):
            return
        else:
            raise ValueError("invalid name: " + repr(name))

    def flatten(self, write):
        if self.contents:
            write("<%s%s>" % (self.__name, self.__attribs))
            closing = "</%s>" % self.__name
            try:
                for x in self.contents:
                    if isstring(x):
                        write(escapeHTML(x))
                    else:
                        x.flatten(write)
            except:
                # If we encountered any exception, try to write the
                # closing tag nevertheless.  This increases our
                # chances that we produce valid XML.
                try:
                    write(closing)
                except:
                    pass
                raise
            write(closing)

        else:
            write("<%s%s/>" % (self.__name, self.__attribs))

    def __repr__(self):
        return "<websupport.Tag instance, name=%s>" % repr(self.__name)

    def toString(self):
        r = StringIO()
        self.flatten(r.write)
        return r.getvalue()

def tag(__name, __contents, **__attribs):
    """Creates a new tag object.

    name - name of the tag
    contents - a sequence objet (or iterator) for the enclosed contents
    attribs - keyword arguments forming attributes
    """
    return Tag(__name, __contents, __attribs)

def emptyTag(__name, **__attribs):
    """A tag without contents.

    name - name of the tag
    attribs - keyword arguments forming attributes
    """
    return Tag(__name, None, __attribs)

def A(url, text=None):
    if text is None:
        text = url
    return tag('a', text, href=str(url))
def STYLE(contents, type='text/css'):
    return tag('style', contents, type=type)
def SCRIPT(contents, type="text/javascript", src=""):
    return tag('script', contents, type=type, src=src)
def LINK(contents, type="text/css", rel="stylesheet", href=""):
    return tag('link', contents, type=type, rel=rel, href=href)
def TITLE(contents):
    return tag('title', contents)
def HTML(head, body):
    return tag('html', (HEAD(head), BODY(body)))
def HEAD(contents):
    return tag('head', contents)
def BODY(contents, onload=None):
    return tag('body', contents, onload=onload)
def H1(contents):
    return tag('h1', contents)
def H2(contents):
    return tag('h2', contents)
def H3(contents):
    return tag('h3', contents)
def P(*contents):
    return Tag('p', contents)
def SPAN(*__contents, **__attribs):
    return Tag('span', __contents, __attribs)
def HR():
    return tag('hr', ())
def BR():
    return tag('br', ())
def CODE(*contents):
    return tag('code', contents)
def EM(*contents):
    return tag('em', contents)
def B(contents):
    return tag('b', contents)
def TABLE(contents):
    return tag('table', contents)
def TR(*contents):
    return tag('tr', contents)
def TH(*contents):
    return tag('th', contents)
def TD(*contents):
    return tag('td', contents)
def FORM(*__contents, **__attribs):
    return Tag('form', __contents, __attribs)
def LABEL(*__contents, **__attribs):
    return Tag('label', __contents, __attribs)
def INPUT(*__contents, **__attribs):
    return Tag('input', __contents, __attribs)
def UL(contents):
    return tag('ul', contents)
def LI(*__contents, **__attribs):
    return Tag('li', __contents, __attribs)
def HEADER(*__contents, **__attribs):
    return Tag('header', __contents, __attribs)
def FOOTER(*__contents, **__attribs):
    return Tag('footer', __contents, __attribs)
def NAV(*__contents, **__attribs):
    return Tag('nav', __contents, __attribs)

def _linkify(match):
    extra = match.group(2)
    if extra is None:
        extra = ""
    link  = match.group(1)
    return "%s%s" % (A(link).toString(), extra)

def linkify(contents):
    contents = re.sub(r'(httpS?://[\w.-]+/.*?)([,\s]|$)', _linkify, contents)
    return contents

def make_table(contents, title=None, caption=None, replacement=None, introduction=None):
    rows = []
    for row in contents:
        cols = []
        if caption and not rows:
            for col in caption:
                cols.append(TH(col))
            rows.append(Tag('tr', cols))
            cols = []

        for col in row:
            cols.append(TD(col))
        rows.append(Tag('tr', cols))
    if rows:
        if not introduction:
            introduction=''
        if not title:
            title=''
        return compose(title, introduction, TABLE(rows))
    else:
        return compose()

def make_pre(lines):
    """Creates a pre-formatted text area."""
    pre = []
    append = pre.append
    for line in lines:
        # turn https:// and http:// into links
        results=re.search("(.*)(?P<url>https?://[^\s]+)(.*)", line)
        if results:
            for group in results.groups():
                if group.startswith('http://') or group.startswith('https://'):
                    append(A(group))
                else:
                    append(group)
        else:
            append(tag("SPAN",line))
        append(BR())
    return tag('pre', pre)

def make_menu(convert, *entries):
    """Creates an unnumbered list of hyperlinks.
    Each entry can be:

    - a pair (URL, LABEL).
      convert(URL) is used as the link, and LABEL as the link text.
    - some non-tuple value.
      This is added as an individual item.
    """
    ul = []
    append = ul.append
    for e in entries:
        if isinstance(e, tuple):
            (relurl, label) = e
            append(LI(A(convert(relurl), label)))
        else:
            append(LI(e))
    return tag('ul', ul)

def make_numbered_list(entries):
    """Creates a numbered list.
    ENTRIES should be a sequence of P objects."""
    ol = []
    append = ol.append
    for e in entries:
        append(LI(e))
    return tag('ol', ol)

def make_list(lst, separator=", "):
    """Creates a list of HTML elements."""
    assert isinstance(lst, list)
    c = []
    if lst:
        for e in lst:
            c.append(e)
            c.append(separator)
        # pop the final separator
        c.pop()
    return Compose(c)

class InvalidPath(Exception):
    """An unknown path was submitted to PathRouter.get"""

class PathRouter:
    """This class maps paths to registered values."""

    def __init__(self):
        self.__map = {}

    def register(self, path, value):
        """Registers the indicated value for the path.

        Path may end with '*' or '**', indicating single-level
        wildcards or multi-level wildcards."""

        m = self.__map
        p = path.split('/')
        if p and not p[0]:
            del p[0]
        for x in range(len(p)):
            element = p[x]
            if element:
                if element in m:
                    m = m[element]
                else:
                    if element == '*':
                        if x + 1 != len(p):
                            raise ValueError('wildcard * in the middle of path')
                        m['*'] = value
                        return
                    if element == '**':
                        if x + 1 != len(p):
                            raise ValueError(
                                  'wildcard ** in the middle of path')
                        m['**'] = value
                        return

                    m_new = {}
                    m[element] = m_new
                    m = m_new
            else:
                raise ValueError("path contains empty element")
        m[''] = value

    def get(self, path):
        """Returns a tuple (VALUE, REMAINING-PATH), for the
        most-specific path matching the given path."""

        m = self.__map
        p = path.split('/')
        while p and not p[-1]:
            del p[-1]
        l = len(p)
        for x in range(l):
            element = p[x]

            # Ignore empty path elements (leadings slash, duplicated
            # slashes).
            if element:
                try:
                    m = m[element]
                except KeyError:
                    if x + 1 == l and '*' in m:
                        # Use '*' only if the remaining path is empty.
                        return (m['*'], tuple(p[x:]))
                    if '**' in m:
                        return (m['**'], tuple(p[x:]))
                    raise InvalidPath()
        try:
            result = m['']
        except KeyError:
            if '*' in m:
                result = m['*']
            elif '**' in m:
                result = m['**']
            else:
                raise InvalidPath()
        return (result, ())

class Result(object):
    """Base class for result objects."""

    def __init__(self):
        self.status = 500
        self.headers = {}

    def flatten(self, write):
        for k, v in self.headers.items():
            write("%s: %s\n" % (k, v))
        write("\n")

    def flatten_later(self):
        """Flattens this result.

        Returns a closure which sends the result using a
        BaseHTTPRequestHandler object passed as argument."""
        def later(req):
            req.send_response(self.status)
            for k, v in self.headers.items():
                req.send_header(k, v)
            req.end_headers()
        return later

class RedirectResult(Result):
    """Permanently redirects the browser to a new URL."""
    def __init__(self, url, permanent=True):
        super(RedirectResult, self).__init__()
        if permanent:
            self.status = 301
        else:
            self.status = 302
        self.headers['Location'] = str(url)

def maybe_encode(obj):
    try:
        return obj.encode()
    except:
        return obj

class HTMLResult(Result):
    """An object of this class combines a status code with HTML contents."""
    def __init__(self, contents, doctype='', status=200):
        super(HTMLResult, self).__init__()
        self.contents = contents
        self.status = status
        self.doctype = doctype
        self.headers['Content-Type'] = 'text/html; charset=UTF-8'

    def flatten(self, write):
        """Invokes write for the response header and all HTML data.
        Includes the doctype declaration."""
        super(HTMLResult, self).flatten(write)
        write("%s\n" % self.doctype)
        self.contents.flatten(write)

    def flatten_later(self):
        headers_later = super(HTMLResult, self).flatten_later()
        buf = StringIO()
        buf.write(self.doctype)
        buf.write('\n')
        def write_both(s):
            try:
                if isinstance(s, unicode):
                    s = s.encode('UTF-8')
            except:
                pass
            finally:
                buf.write(s)
        self.contents.flatten(write_both)
        buf = buf.getvalue()
        buf = maybe_encode(buf)
        self.headers['Content-Length'] = str(len(buf))
        def later(req):
            headers_later(req)
            if req.command != 'HEAD':
                req.wfile.write(buf)
        return later

class BinaryResult(Result):
    """An object of this class combines a status code with HTML contents."""
    def __init__(self, contents,
                 mimetype='application/octet-stream', status=200):
        super(BinaryResult, self).__init__()
        self.contents = contents
        self.status = status
        self.headers['Content-Type'] = mimetype
        self.headers['Content-Length'] = str(len(self.contents))

    def flatten(self, write):
        """Invokes write for the response header and the binary data."""
        super(BinaryResult, self).flatten(write)
        write(self.contents)

    def flatten_later(self):
        headers_later = super(BinaryResult, self).flatten_later()
        def later(req):
            headers_later(req)
            if req.command != 'HEAD':
                req.wfile.write(maybe_encode(self.contents))
        return later

class WebServiceBase:
    def __init__(self):
        self.router = PathRouter()

    def register(self, path, method):
        """Requests that method is invoked if path is encountered.

        The path has the syntax required by PathRouter.register.  The
        method should be a function taking several arguments

        - the remaining path
        - a dictionary for the request parameters
        - a URLFactory object

        The method is expected to return a HTMLResult object.
        """
        self.router.register(path, method)

    def html_dtd(self):
        """Returns the DOCTYPE declaration to be used for HTML documents.
        Can be overridden."""
        return '<!DOCTYPE html>'

    def add_title(self, title, body, head_contents=None, body_attribs={}):
        """Takes a sequence of HTML objects and wraps them in 'body'
        and 'html' tags.  Puts title in front of it, and optionally
        includes the head_contents material.  The attributes of the
        body element are taken from the body_attribs dictionary."""
        t = TITLE(title)
        if head_contents is None:
            head_list = [t]
        else:
            if isinstance(head_contents, HTMLBase):
                head_list = [head_contents]
            else:
                head_list = list(head_contents)
            head_list.append(t)
        if isinstance(body, HTMLBase):
            body_list = [body]
        else:
            body_list = list(body)
        body_list[:0] = (HEADER(H1(title)),)

        return tag('html',
                   (HEAD(head_list), Tag('body', body_list, body_attribs)))

    def pre_dispatch(self, url):
        """Invoked by handle prior to calling the registered handler."""
        pass

class WebService(Service, WebServiceBase):
    "CGI service implemented using servinvoke"
    def __init__(self, socket_name):
        Service.__init__(self, socket_name)
        WebServiceBase.__init__(self)

    def __writeError(self, result, code, msg):
        result.write('Status: %d\nContent-Type: text/plain\n\n%s\n'
                     % (code, msg))

    def handle(self, args, environment, data, result):
        params = cgi.parse(data, environment)
        path = environment.get('PATH_INFO', '')
        server_name = environment.get('SERVER_NAME', '')
        server_port = environment.get('SERVER_PORT', '')
        if server_port and server_port != 80:
            server_name = server_name + ":" + server_port
        script_name = environment.get('SCRIPT_NAME', '')

        try:
            (method, remaining) = self.router.get(path)
        except InvalidPath:
            self.__writeError(result, 404, "page not found")
            return
        self.pre_dispatch()
        url = URLFactory(server_name, script_name, path, params)
        r = method(remaining, params, url)
        assert isinstance(r, Result), repr(r)
        r.flatten(result.write)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

RE_BASE_URL = re.compile(r'^(https?)://([^/]+)(.*)')

class WebServiceHTTP(WebServiceBase):
    def __init__(self, socket_name):
        WebServiceBase.__init__(self)
        (base_url, address, port) = socket_name
        self.lock = threading.Lock()

        self.__parse_base_url(base_url)

        service_self = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                (method, path, remaining, params) = self.route()
                if path is None:
                    return

                url = URLFactory(service_self.server_name,
                                 service_self.script_name,
                                 path, params,
                                 secure=service_self.secure)

                service_self.lock.acquire()
                try:
                    service_self.pre_dispatch()
                    r = method(remaining, params, url)
                    assert isinstance(r, Result), repr(r)
                    result = r.flatten_later()
                finally:
                    service_self.lock.release()
                result(self)
            do_HEAD = do_GET

            def __parse_path(self):
                pos = self.path.find('?')
                if pos < 0:
                    return (self.path, {})
                path = self.path[:pos]
                if path[:1] != '/':
                    path = '/' + path
                params = parse_qs(self.path[pos + 1:])
                return (path, params)

            def route(self):
                (path, params) = self.__parse_path()
                prefix_len = len(service_self.script_name)
                prefix = path[0:prefix_len]
                result = None
                if prefix == service_self.script_name:
                    suffix = path[prefix_len:]
                    try:
                        (method, remaining) = \
                            service_self.router.get(suffix)
                        return (method, suffix, remaining, params)
                    except InvalidPath:
                        pass
                self.send_error(404, "page not found")
                return (None, None, None, None)

        self.server = ThreadingHTTPServer((address, port), Handler)

    def run(self):
        self.server.serve_forever()

    def __parse_base_url(self, url):
        m = RE_BASE_URL.match(url)
        if m is None:
            raise ValueError("invalid base URL: " + url)
        self.secure = m.group(1) == "https"
        self.server_name = m.group(2)
        self.script_name = m.group(3)


def __test():
    assert str(URL("")) == ""
    assert str(URL("abc")) == "abc"
    assert str(URL(" ")) == " "
    assert str(URL("&")) == "&"

    u = URLFactory(server_name=None, script_name=None)
    assert str(u.absolute("http://www.enyo.de/")) == "http://www.enyo.de/"
    assert str(u.absolute("http://www.enyo.de/", t='123')) \
           == "http://www.enyo.de/?t=123"
    assert str(u.scriptRelative("/a/b", t='123')) == "/a/b?t=123"
    assert str(u.scriptRelativeFull("/a/b", t='123')) \
           == "http://localhost/a/b?t=123"

    u = URLFactory(server_name=None, script_name=None, secure=True)
    assert str(u.absolute("http://www.enyo.de/")) == "http://www.enyo.de/"
    assert str(u.absolute("http://www.enyo.de/", t='123')) \
           == "http://www.enyo.de/?t=123"
    assert str(u.scriptRelative("/a/b", t='123')) == "/a/b?t=123"
    assert str(u.scriptRelativeFull("/a/b", t='123')) \
           == "https://localhost/a/b?t=123"

    u = URLFactory(server_name='localhost.localdomain',
                   script_name='/cgi-bin/test.cgi')
    assert str(u.scriptRelative("a/b", t='123')) \
           == "/cgi-bin/test.cgi/a/b?t=123"
    assert str(u.scriptRelativeFull("a/b", t='123=')) \
           == "http://localhost.localdomain/cgi-bin/test.cgi/a/b?t=123%3D"

    assert P("").toString() == '<p></p>'
    assert P(" ").toString() == '<p> </p>'
    assert P("&").toString() == '<p>&amp;</p>'
    assert P("\"").toString() == '<p>"</p>'
    assert P("<").toString() == '<p>&lt;</p>'
    assert P(">").toString() == '<p>&gt;</p>'
    assert P(">").toHTML().toString() == '<p>&gt;</p>'
    assert FORM(method='get').toString() == '<form method="get"/>'
    assert SPAN("green", _class="red").toString() \
           == '<span class="red">green</span>'
    assert TD(A("http://www.example.net/", "example")).toString() \
           == '<td><a href="http://www.example.net/">example</a></td>'
    #assert make_pre(['a', 'b']).toString() == '<pre>a\nb\n</pre>'

    s = StringIO()
    RedirectResult(u.scriptRelativeFull("123")).flatten(s.write)
    assert s.getvalue() == '''Location: http://localhost.localdomain/cgi-bin/test.cgi/123

'''

    assert make_menu(u.scriptRelative,
                     ("123", "A"),
                     ("456", "B")).toString() == \
                     '<ul><li><a href="/cgi-bin/test.cgi/123">A</a></li><li><a href="/cgi-bin/test.cgi/456">B</a></li></ul>'

    pr = PathRouter()
    pr.register('', "root")
    pr.register('/*', "default")
    pr.register('/abc', "/abc")
    pr.register('/a/bc', "/a/bc")
    pr.register('ab/c', "/ab/c")
    pr.register('/a', "/a")
    pr.register('/a/**', "/a/**")
    pr.register('/a/*', "/a/*")

    assert pr.get("") == ("root", ())
    assert pr.get("/") == ("root", ())
    assert pr.get("//") == ("root", ())
    assert pr.get("/xyz") == ("default", ("xyz",))
    assert pr.get("/a//xyz/") == ("/a/*", ("xyz",))
    assert pr.get("/a//xyz/123") == ("/a/**", ("xyz", "123"))
    assert pr.get("/abc") == ("/abc", ())

    assert linkify('foo bar moo') == 'foo bar moo'
    assert linkify('http://domain.tld/foo.cgi?bar=moo&test') == A('http://domain.tld/foo.cgi?bar=moo&test').toString()
    assert linkify('as seen in http://foo.tld/bar/moo.txt, ...') == 'as seen in %s, ...' % A('http://foo.tld/bar/moo.txt').toString()

if __name__ == "__main__":
    __test()
