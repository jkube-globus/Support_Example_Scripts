export EP_UUID=2fa2ecca-a0f4-427e-a607-c3295f5c13be
export EP_TYPE=new
for GCOLL in `globus gcs collection list --filter guest-collections ${EP_UUID} -F json|grep \"id\" | cut -f4 -d"\""`
do echo guest collection $each ------ | tee -a ${EP_TYPE}_endpoint/${GCOLL}.acls
        globus api transfer GET /endpoint/${GCOLL}/access_list | tee -a ${EP_TYPE}_endpoint/${GCOLL}.acls
done
