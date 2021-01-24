import subprocess
import json
import os, shutil
from glob import glob
import argparse

artifacts_file = 'artifacts.json'
working_path = '/tmp/forensics/'
memdump_path = working_path + 'memdump/'
packed_evidence_filename = 'forensics_complete.tar.gz'  # Default value if parameter is missing

print("""
////////////////////////////////////////////////////////////////////////////
| Script to retrieve artifacts like files and commands output,             |
| and perform a memory dump from a Linux server.                           |
| Artifacts are described in artifacs.json file.                           |
| Wildcards are allowed to filenames and directories.                      |
| Multiple files/directories are allowed per name.                         |
| Only one COMMAND is allowed per name.                                    |
| Must run as root.                                                        |
|                                                                          |
| Author: Guido Bernat.                                                    |
////////////////////////////////////////////////////////////////////////////

""")




# Install necessary SO packages to do all tasks
def install_packages():
    print('>> Installing SO packages...')
    cmds = [['sudo', 'yum', 'install', 'git', '-y'],
            ['sudo', 'yum', 'install', 'kernel-devel-'+os.uname().release, '-y'],
            ['sudo', 'yum', 'install',  'gcc', '-y']]
    try:
        for cmd in cmds:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        print("[ERROR] Couldn't install packages. Only RHEL type Linux allowed.")


# Memory dump
def do_memory_dump():
    print('\n>> Performing memory dump...')
    orig_cwd = os.getcwd()
    mem_dump_cmd = ['git', 'clone', 'https://github.com/504ensicsLabs/LiME', memdump_path]
    try:
        res = subprocess.run(mem_dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.chdir(memdump_path + 'src')
        print('   loading kernel module...')
        res = subprocess.run('make', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('   dumping Memory...')
        cmd = "insmod " + glob('lime-*.ko')[0] + " 'path=" + working_path + "memory_dump.mem format=lime'"
        #print(cmd)
        res = subprocess.run(cmd, shell=True)
        print('   compressing memory image...')
        res = subprocess.run(['tar', '-czf', working_path + 'memory_dump.mem.tar.gz', working_path + 'memory_dump.mem'], stdout=None, stderr=subprocess.PIPE)
        os.remove(working_path+'memory_dump.mem')
        shutil.rmtree(memdump_path)
        #res = subprocess.run(['make', 'clean'])
        print('   Memory dump complete!')
    except:
        print('   ! Error performing memory dump.')
    # Remove loaded kernel module, to return to initial state     
    try:
        res = subprocess.run(['rmmod', 'lime'], stdout=None, stderr=subprocess.PIPE)
    except:
        pass
    os.chdir(orig_cwd)


# Collect files and process output detailed in artifacs.json
def collect_forensic_evidence():
    # Load artifact list 
    print('\n>> Loading artifact list...')
    with open(artifacts_file) as f:
        artifacts = json.load(f)

    # Retrieve artifacts, and compress
    print('>> Retrieving artifacts.')
    for art in artifacts:
        #print('Name: ' + art['name'] + ' Type: ' + art['type'] + ' Value: ' + str(art['attributes']) )
        if art['type'] == 'FILE':
            for p in art['attributes']:
                for i in glob(p):
                    print('   Working on FILE: ' + i)
                    try:
                        res = subprocess.run(['tar', '-czf', working_path + art['name']+ '_' + i[1:].replace('/','_') + '.tar.gz', i], stdout=None, stderr=subprocess.PIPE)
                        os.remove(i)
                    except:
                        print('   ! Error copying or compressing FILE.')

        elif art['type'] == 'COMMAND':
            try:
                cmd_file = working_path + art['name']
                print('   Working on COMMAND: ' + str(art['attributes']))
                c = open(cmd_file, 'w')
                res = subprocess.run(art['attributes'], stdout=c, stderr=subprocess.PIPE)
                c.close()
                res = subprocess.run(['tar', '-czf', cmd_file + '.tar.gz', cmd_file], stdout=None, stderr=subprocess.PIPE)
                os.remove(cmd_file)
            except:
                print('   ! Error executing command or compressing output.')

        else:
            print('   Artifact type: ' + art['type'] + ' not recognized.')



# Cleaning
def do_cleaning():
    print('>> Almost done. Cleaning all the mess...')
    try:
        #pass
        shutil.rmtree(working_path)
    except:
        print('   ! Error trying to remove local forensic data from ' + working_path)





#########################
# Main
#########################

def main(params):

    print("I'm going to do this:\n"+str(params).replace('\'','').replace('{', '').replace('}','').replace(',','\n')+'\n')

    # Create temp working directory if not exist
    if not os.path.exists(working_path):
        os.mkdir(working_path)
    #os.chdir(working_path)

    # Install necessary SO packages
    install_packages()

    # Execute memory dump
    if params['memory_dump']:
        do_memory_dump()
    
    # Get files and commands output
    collect_forensic_evidence()

    try:
        res = subprocess.run(['tar', '-czf', working_path + params['output_filename'], working_path], stdout=None, stderr=subprocess.PIPE)
        print('\n>> File ' + working_path + params['output_filename'] + ' contains all the collected evidence.')
    except:
        print('   ! Error creating final ' + params['output_filename'])

    # Remove temp files
    if not params['conserve_files']:
        do_cleaning()

    print('\nDone!\n')


# From command line arguments:
if __name__=='__main__':
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('--no-memory-dump', required=False, dest='no_memory_dump', action='store_true', help='Do not execute memory dump. --> default: false (make memory dump)')
    my_parser.add_argument('--conserve-local-forensics', required=False, dest='conserve_forensics', action='store_true', help='Do not delete forensinc files gathered in destination server after finishing tasks. --> default: false (delete tmp files in remote server)')
    my_parser.add_argument('--output-filename', required=False, dest='results_filename', type=str, default=packed_evidence_filename, help='Filename of the .tar.gz resultant forensics data gathered and memory dump. --> default: '+packed_evidence_filename)
    args = my_parser.parse_args()

    argsh = { 
        'memory_dump': not args.no_memory_dump,
        'conserve_files': args.conserve_forensics,
        'output_filename': args.results_filename
    } 

    main(argsh)


