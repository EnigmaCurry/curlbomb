pkgbase=('curlbomb')
pkgname=('curlbomb')
_module='curlbomb'
pkgver='1.0.2'
pkgrel=0
pkgdesc="A personal HTTP server for serving one-time-use bash scripts"
url="https://github.com/EnigmaCurry/curlbomb"
depends=('python')
makedepends=('python-setuptools')
license=('MIT')
arch=('any')
source=("https://pypi.python.org/packages/source/c/curlbomb/curlbomb-${pkgver}.tar.gz")
md5sums=('1468d3f71469bd2961688e9674d2a993')

package() {
    depends+=()
    cd "${srcdir}/${_module}-${pkgver}"
    python setup.py install --root="${pkgdir}"
}
