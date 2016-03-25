pkgbase=('curlbomb')
pkgname=('curlbomb')
_module='curlbomb'
pkgver='1.0.3'
pkgrel=0
pkgdesc="A personal HTTP server for serving one-time-use bash scripts"
url="https://github.com/EnigmaCurry/curlbomb"
depends=('python')
makedepends=('python-setuptools')
license=('MIT')
arch=('any')
source=("https://pypi.python.org/packages/source/c/curlbomb/curlbomb-${pkgver}.tar.gz")
md5sums=('837addfb30ad99c20348de0f361bbb61')

package() {
    depends+=()
    cd "${srcdir}/${_module}-${pkgver}"
    python setup.py install --root="${pkgdir}"

    python setup.py build_manpage --output=curlbomb.1 --parser=curlbomb:argparser --appname=curlbomb
    mkdir -p ${pkgdir}/usr/share/main/man1
    mv curlbomb.1 ${pkgdir}/usr/share/main/man1
}
