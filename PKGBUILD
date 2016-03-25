pkgbase=('curlbomb')
pkgname=('curlbomb')
_module='curlbomb'
pkgver='1.0.5'
pkgrel=0
pkgdesc="A personal HTTP server for serving one-time-use bash scripts"
url="https://github.com/EnigmaCurry/curlbomb"
depends=('python')
makedepends=('python-setuptools')
license=('MIT')
arch=('any')
source=("https://pypi.python.org/packages/source/c/curlbomb/curlbomb-${pkgver}.tar.gz")
md5sums=('3dfc9a6cb1a31b4c469c08ee1710e2b3')

package() {
    depends+=()
    cd "${srcdir}/${_module}-${pkgver}"
    python setup.py install --root="${pkgdir}"

    python build_manpage.py
    mkdir -p ${pkgdir}/usr/share/main/man1
    mv curlbomb.1 ${pkgdir}/usr/share/main/man1
}
