DEV="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
DIST=${DEV}"/../dist"
ROOT=${DEV}"/.."

mkdir -p $DIST
cp $ROOT/readme.md $DIST/
cp $DEV/.env.template $DIST/
cp $DEV/keygen.sh $DIST/
cp $DEV/setup.sh $DIST/
cp $ROOT/package.json $DIST/
cp $ROOT/package-lock.json $DIST/
cp -r $ROOT/src/lib $DIST/
