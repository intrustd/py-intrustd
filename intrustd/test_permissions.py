import pytest

from .permissions import Permissions, parse_template, LiteralToken, PlaceholderToken, ReValidator, mkperm, Placeholder

perms = Permissions('intrustd+perm://photos.intrustd.com')

CommentAllPerm = perms.permission('/comment')
GalleryPerm = perms.permission('/gallery')
UploadPerm = perms.permission('/upload')
EditPerm = perms.permission('/edit/<photo_id>')
DeletePerm = perms.permission('/delete/<photo_id>')

@perms.permission('/comment/<photo_id>')
class CommentPerm(object):
    def __init__(self, photo_id=None):
        if photo_id is None:
            raise ValueError("Expected photo_id")

        self.photo_id = photo_id

    def search(self, search):
        for _ in search.search(CommentAllPerm):
            print("Satisfied CommentPerm({}) via ComentAllPerm".format(self.photo_id))
            search.satisfy()

        for _ in search.search(EditPerm(photo_id=self.photo_id)):
            for _ in search.search(DeletePerm(photo_id=self.photo_id)):
                search.satisfy()

    def validate(self):
        return False

def test_permission():
    perm = CommentPerm(photo_id='a'*32)
    assert perm.is_complete
    assert perm.url == 'intrustd+perm://photos.intrustd.com/comment/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

def test_permissionset():
    s = perms.set('/comment', GalleryPerm)
    assert len(s) == 2

    assert CommentAllPerm in s
    assert CommentPerm(photo_id='a' * 32) in s
    assert CommentPerm(photo_id='b' * 32) in s

def test_disjunction():
    s = perms.set('/edit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '/delete/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

    assert CommentAllPerm not in s
    assert CommentPerm(photo_id = 'a'*32) in s

def test_disjunction2():
    s = perms.set('/edit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '/delete/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab')

    assert CommentAllPerm not in s
    assert CommentPerm(photo_id = 'a'*32) not in s
    assert CommentPerm(photo_id = 'a'*31 + 'b') not in s

    s.add('intrustd+perm://photos.intrustd.com/delete/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    assert CommentPerm(photo_id = 'a'*32) in s

def test_parse_eot():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    with pytest.raises(ValueError) as excinfo:
        TestPerm = perms.permission('/edit/<photo_id')
    assert 'End of template' in str(excinfo.value)

def test_parse_unnamed():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    with pytest.raises(ValueError) as excinfo:
        TestPerm = perms.permission('/edit/<>')
    assert 'Empty string' in str(excinfo.value)

def test_parse_invalidchar():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    with pytest.raises(ValueError) as excinfo:
        TestPerm = perms.permission('/edit/<hello-world>')
    assert 'Invalid character - in' in str(excinfo.value)

def test_parse_validate_arg():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    with pytest.raises(ValueError) as excinfo:
        TestPerm = perms.permission('/edit/<hello-world ~"[A-Za-z0-9]{32}">')
    assert 'Invalid character - in' in str(excinfo.value)

def test_parse_validator_invalidchar():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    with pytest.raises(ValueError) as excinfo:
        TestPerm = perms.permission('/edit/<hello_world test@blah:"[A-Za-z0-9]{32}">')
    assert 'Invalid character @ in' in str(excinfo.value)

def test_parse_dup():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    with pytest.raises(ValueError) as excinfo:
        TestPerm = perms.permission('/edit/<photo_id>/blah/<photo_id>/blah/<okay>')
    assert 'Duplicate token photo_id' in str(excinfo.value)

def test_parse_placeholders():
    placeholders, _ = parse_template('/comment/<test1>/blah/<test2><test3>/blah/test4/<test5>')

    assert placeholders == set(['test1', 'test2', 'test3', 'test5'])

def test_escape_char():
    placeholders, res = parse_template('/comment/<test1 ~"[A-Z]{32}\n">')
    assert placeholders == set(['test1'])
    assert len(res) == 2

    assert isinstance(res[0], LiteralToken)
    assert res[0].literal == '/comment/'

    assert isinstance(res[1], PlaceholderToken)
    assert res[1].name == 'test1'
    assert isinstance(res[1].validator, ReValidator)
    assert res[1].validator.regex_str == '[A-Z]{32}\n'

def test_re():
    perms = Permissions('intrustd+perm://app.intrustd.com')

    TestPerm = perms.permission('/edit/<photo_id ~\'[A-Za-z0-9]{32}\'>/blah/<what ~"foo|bar">')

    assert perms.parse_perm('/comment/1pfnq9v0cg42v9xz5xd1whn9l0iygdhlwrmvaljwxdkx8l2wyrkx/blah/bar') is None
    assert perms.parse_perm('/edit/1pfnq9v0cg42v9xz5xd1whn9l0iygdhl/blah/foo') == \
        TestPerm(photo_id='1pfnq9v0cg42v9xz5xd1whn9l0iygdhl', what='foo')
    assert TestPerm(what='bar').pattern == 'intrustd+perm://app.intrustd.com/edit/<photo_id ~\'[A-Za-z0-9]{32}\'>/blah/bar'

def test_mkperm():
    mk = mkperm(CommentPerm, photo_id=Placeholder('image_hash'))
    assert mk(image_hash='2ganq9v0cg42v9xz5xd1whn9l0iygdhl') == CommentPerm(photo_id='2ganq9v0cg42v9xz5xd1whn9l0iygdhl')
