import os
import django
import subprocess32 as subprocess

# Django stuff

# Django specific settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

django.setup()

# Import your models for use in your script
from db.models import *
from django.db.models import F

LOCAL_PATH = "/Datastore0/Photos"
REMOTE_PATH = "/mnt/dave_acd/Pictures"
ACD_PATH = "/Pictures"
ACD_CMD = "acd_cli"
SHA1SUM_CMD = "sha1sum"

SHA1SUM_OF_NOTHING = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

# These should be in lower case
WHITELIST_SUFFIX = [
    "jpg",
    "png",
    "dng",
    "nef",
    "xmp",
]

# These are case sensitive
BLACKLIST_CONTAINS = [
    "Cisco Brand",
]


def _acd_cli_mkdir(remote_path):
    subprocess.check_output([ACD_CMD, "mkdir", "-p", remote_path], stderr=subprocess.STDOUT)


def _acd_cli_upload(local_files, remote_path):
    # type: (list, str) -> int
    subprocess_cmds = [ACD_CMD, "upload", "-x8", "-r2", "-o", "-q"] + local_files + [remote_path]
    return subprocess.call(subprocess_cmds)


def _acd_cli_mv(old_path, new_path):
    return subprocess.call([ACD_CMD, "mv", old_path, new_path])


def _acd_cli_sync():
    subprocess.call([ACD_CMD, "sync"])


def _make_sh_friendly(cmd):
    return cmd.replace(" ", "\\ ")\
        .replace('(', "\\(")\
        .replace(')', "\\)")\
        .replace('&', "\\&")\
        .replace('\'', "\\\'")


def _os_sha1sum(filepath):
    return subprocess.check_output([SHA1SUM_CMD, filepath]).split(' ', 1)[0]


# returns a "hash" of a directory, which is really just the has of the ls -l listings
def _os_sha1sum_dir(dirpath):
    if not os.listdir(dirpath):
        # dir is empty, return hash of nothing
        return SHA1SUM_OF_NOTHING

    hash_path = _make_sh_friendly("{}".format(dirpath))
    full_cmd = "ls -l {} | sha1sum".format(hash_path)
    return subprocess.check_output(full_cmd, shell=True).split(' ', 1)[0]


def _get_or_make_entry(short_path, all_entries=None):
    if not all_entries:
        all_entries = Entry.objects.all()

    entry_set = all_entries.filter(path=short_path)

    new_entry = False
    if not entry_set.exists():
        entry = Entry(path=short_path)
        new_entry = True
    else:
        entry = entry_set[0]

    return entry, new_entry


#@profile
def _walk_dir_update_hashes(is_local):
    if is_local:
        search_path = LOCAL_PATH
    else:
        search_path = REMOTE_PATH

    rplen = len(search_path)
    all_entries = Entry.objects.all()

    for root, dirs, files in os.walk(search_path):

        # Take the fingerprint of the directory, skip if there are no changes
        short_path = root[rplen:]
        entry, is_new = _get_or_make_entry(short_path, all_entries)
        entry.is_dir = True

        dir_hash = _os_sha1sum_dir(root)
        if is_local:
            if dir_hash != entry.local_shasum:
                # check to see if dir was moved, ignoring empty directories
                if dir_hash != SHA1SUM_OF_NOTHING:
                    old_entry = all_entries.filter(local_shasum=dir_hash)
                    if old_entry.exists():
                        entry = old_entry[0]
                        entry.prev_path = entry.path
                        entry.path = short_path
                        entry.save()
                        continue

                # Indicates that directory has changed, need to check every file inside
                entry.local_shasum = dir_hash
                entry.save()
            else:
                continue

        for filename in files:
            filepath = os.path.join(root, filename)
            short_path = filepath[rplen:]

            # Ignore empty files
            if os.stat(filepath).st_size == 0:
                continue

            file_m_time = int(os.path.getmtime(filepath))

            entry, changed = _get_or_make_entry(short_path, all_entries)

            if is_local and entry.last_check_date >= file_m_time:
                continue

            file_hash = ""
            attempts = 0

            while attempts < 3 and not file_hash:
                try:
                    file_hash = _os_sha1sum(filepath)

                except IOError:
                    pass
                finally:
                    attempts += 1

            if not file_hash:
                print "Could not read", filepath
                continue

            if is_local and entry.local_shasum != file_hash:
                # Check to see if this file has been moved
                old_entry = all_entries.filter(local_shasum=file_hash)
                if old_entry.exists():
                    entry = old_entry[0]
                    entry.prev_path = entry.path
                    entry.path = short_path
                else:
                    entry.local_shasum = file_hash

                changed = True
            elif not is_local:
                if entry.acd_shasum != file_hash:
                    entry.acd_shasum = file_hash
                    changed = True

                if len(entry.local_shasum) == 0:
                    entry.local_shasum = file_hash
                    changed = True

            if entry.last_check_date < file_m_time:
                entry.last_check_date = file_m_time
                changed = True

            if changed:
                print "Detected change to: ", filepath, "--", file_hash
                entry.save()


def update_local_sha_hashes():
    print "=" * 50
    print "Updating local file hashes"
    print "=" * 50

    _walk_dir_update_hashes(True)


def update_acd_sha_hashes():
    if not os.path.exists(REMOTE_PATH):
        print "ACD Not mounted"
        return

    _walk_dir_update_hashes(False)


# Filters out a list of entries to only include whitelist suffixes and exclude blacklist "Contains" entries
def _filter_changelist(entry_list, whitelist_dir=False):
    # Filter to only contain whitelisted
    if not whitelist_dir:
        entry_list = [entry for entry in entry_list if entry.path.lower().endswith(tuple(WHITELIST_SUFFIX))]
    else:
        entry_list = [entry for entry in entry_list if entry.path.lower().endswith(tuple(WHITELIST_SUFFIX))
                      or entry.is_dir]

    # Filter out Blacklisted "contains" entries
    entry_list = [entry for entry in entry_list if not any(blacklistable in entry.path
                                                           for blacklistable in BLACKLIST_CONTAINS)]

    return entry_list


def get_changelist():
    print "=" * 50
    print "Getting changelist of files"
    print "=" * 50

    # Get all files where the acd sum is not the same as the local sum, has not been moved, and is not a dir
    changed_files_qset = Entry.objects.exclude(acd_shasum=F('local_shasum')).filter(prev_path="").exclude(is_dir=True).all()
    changed_entries = [entry for entry in changed_files_qset]
    changed_entries = _filter_changelist(changed_entries)

    # Get all moved files
    # moved_files_qset = Entry.objects.exclude(prev_path="").exclude(is_dir=True).all()
    moved_files_qset = Entry.objects.exclude(prev_path="").all()
    moved_entries = [entry for entry in moved_files_qset]
    moved_entries = _filter_changelist(moved_entries, True)

    for entry in changed_entries:
        print "Detected changed/NEW file:", entry.path

    for entry in moved_entries:
        print "Detected moved:", entry.prev_path, "to", entry.path

    return changed_entries, moved_entries


def refresh_db():
    print "=" * 50
    print "Removing nonexistent entries from the DB"
    print "=" * 50
    for entry in Entry.objects.all():
        filepath = "{}{}".format(LOCAL_PATH, entry.path)
        if not os.path.exists(filepath):
            print "Removing", filepath, "from DB"
            entry.delete()


def upload_files(changed, moved):
    print "=" * 50
    print "Uploading to ACD"
    print "=" * 50
    bundles = dict()
    all_upload_success = True

    # Upload changed files
    # Bundle items into a dictionary grouped by path so they can be uploaded in bulk
    for entry in changed:
        directory = os.path.dirname(entry.path)

        if directory not in bundles:
            bundles[directory] = list()

        bundles[directory].append(entry)

    # Loop over bundles and upload all at once
    for directory, entries in bundles.iteritems():
        print "Processing", directory
        remote_path = "{}{}".format(ACD_PATH, directory)

        # upload 8 files at a time
        sliced_entries = list()
        for i in xrange(0, len(entries), 8):
            sliced_entries.append(entries[i:i+8])

        for a_slice in sliced_entries:
            slice_paths = ["{}{}".format(LOCAL_PATH, entry.path) for entry in a_slice]
            for path in slice_paths:
                print path

            # try to upload to acd
            # Mkdir first
            _acd_cli_mkdir(remote_path)
            rv = _acd_cli_upload(slice_paths, remote_path)

            print "---------------- Finished Upload ----------------"
            if rv == 0:
                for entry in a_slice:
                    entry.acd_shasum = entry.local_shasum
                    entry.save()
            else:
                all_upload_success = False

    # Move files that have been moved
    for entry in moved:
        # Check corner case of a "moved" file that never existed in ACD,
        # likely due to a failed upload then a move
        if not entry.is_dir and entry.acd_shasum == "":
            # Clear out prev_path, let the uploader handle it as a *new* file next time
            entry.prev_path = ""
            entry.save()
            continue

        directory = os.path.dirname(entry.path)
        remote_path = "{}{}".format(ACD_PATH, directory)
        if not entry.is_dir:
            _acd_cli_mkdir(remote_path)
        old_path = "{}{}".format(ACD_PATH, entry.prev_path)
        print "Moving", old_path, "to", remote_path
        rv = _acd_cli_mv(old_path, remote_path)

        if rv == 0:
            entry.prev_path = ""
            entry.save()
        else:
            all_upload_success = False

    return all_upload_success


# @profile
def main():
    print "Running ACD Uploader"

    # Only do this once
    # update_acd_sha_hashes()

    for i in xrange(0, 10):
        update_local_sha_hashes()

        changed_entries, moved_entries = get_changelist()

        if len(changed_entries) == 0 and len(moved_entries) == 0:
            print "No File contents changed, exiting"
            return

        _acd_cli_sync()

        all_success = upload_files(changed_entries, moved_entries)

        if all_success:
            break
        else:
            print "Failure detected, retrying"

    # TODO: Figure out file deletion handling!

    # refresh_db()






if __name__ == "__main__":
    main()
