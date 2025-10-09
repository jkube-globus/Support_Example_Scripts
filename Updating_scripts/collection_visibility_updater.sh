export VISIBILITY=public
for COLL in `gcs collection list -F json|grep \"id\" | cut -f4 -d"\""`
do echo Updating  collection ${COLL} to ${VISIBILITY}
        gcs collection update ${COLL} --${VISIBILITY}
done
