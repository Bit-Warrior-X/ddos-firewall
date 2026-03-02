VERSION=`date +%Y%m%d%H`
RELEASE=1
rpmbuild \
    --define "_topdir %(echo $PWD)" \
    --define "version ${VERSION}" \
    --define "release ${RELEASE}" \
    -ba SPECS/skc-libmaxminddb.spec
