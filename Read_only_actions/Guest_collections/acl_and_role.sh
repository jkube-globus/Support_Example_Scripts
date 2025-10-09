export EP_UUID=2fa2ecca-a0f4-427e-a607-c3295f5c13be
export EP_TYPE=new

mkdir -p {new,source}_endpoint/{perms,roles}
for GCOLL in `globus gcs collection list --filter guest-collections ${EP_UUID} -F json|grep \"id\" | cut -f4 -d"\""`
do
		# Gather Permissions
		echo guest collection ${GCOLL} ------ | tee -a ${EP_TYPE}_endpoint/perms/${GCOLL}.perms
        globus api transfer GET /endpoint/${GCOLL}/access_list | tee -a ${EP_TYPE}_endpoint/perms/${GCOLL}.perms

		# Gather Roles
        echo guest collection ${GCOLL} ------ | tee -a ${EP_TYPE}_endpoint/roles/${GCOLL}.roles
        globus api transfer GET /endpoint/${GCOLL}/role_list | tee -a ${EP_TYPE}_endpoint/roles/${GCOLL}.roles
done
