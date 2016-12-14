# Do things in edx-platform

clean:
	# Remove all the git-ignored stuff, but save and restore things marked
	# by start-noclean/end-noclean.
	sed -n -e '/start-noclean/,/end-noclean/p' < .gitignore > /tmp/private-files
	tar cf /tmp/private.tar `git ls-files --exclude-from=/tmp/private-files --ignored --others`
	git clean -fdX
	tar xf /tmp/private.tar

bootstrap:  # Provision the service for devstack
	paver update_db --settings=devstack
	python ./manage.py lms --settings=devstack manage_user edx edx@example.com --superuser --staff'
    echo "from django.contrib.auth import get_user_model; User = get_user_model(); user = User.objects.get(username=\"edx\"); user.set_password(\"edx\"); user.save()" | python /edx/app/edxapp/edx-platform/manage.py lms shell  --settings=devstack
    paver update_assets --settings=devstack
