# -*- coding: utf-8 -*-
import ctypes
import os
import platform
# import pythoncom

from xml.etree.cElementTree import ElementTree

from .system_info import System
from ..checks.path_manipulation_checks import get_path_info
from ..objects.taskscheduler import Taskscheduler


class GetTaskschedulers(object):
    def __init__(self):
        self.task_directory = os.path.join(os.environ.get('systemroot'), 'system32\Tasks')
        s = System()

        self.disable_redirection = False
        if s.isx64:
            self.disable_redirection = True

    def tasks_list(self):
        tasks = []

        # manage tasks for windows XP
        if platform.release() == 'XP' or platform.release() == '2003':
            pass
        # try:
        # 	from win32com.taskscheduler import taskscheduler

        # 	ts = pythoncom.CoCreateInstance(
        # 										taskscheduler.CLSID_CTaskScheduler,
        # 										None,
        # 										pythoncom.CLSCTX_INPROC_SERVER,
        # 										taskscheduler.IID_ITaskScheduler
        # 									)
        # except:
        # 	return False

        # Loop through all scheduled task
        # tasks = ts.Enum()
        # for job in tasks:
        # 	task = ts.Activate(job)

        # 	t = Taskscheduler()
        # 	t.name = job

        # check if the tasks file has write access
        # taskpath = '%s%s%s%s%s' % (os.environ['systemroot'], os.sep, 'Tasks', os.sep, job)
        # TO DO
        # if os.path.exists(taskpath):
        # 	if checkPermissions(taskpath):
        # 		results = results + '<strong><font color=ff0000>Write access on: ' + taskpath + '</font></strong><br/>\n'

        # run as
        # try:
        # 	t.runas = task.GetCreator()
        # except:
        # 	pass

        # path of the exe file
        # try:
        # task.GetApplicationName()
        # except:
        # pass

        # check the permission of the executable
        # try:
        # 	test = checkPermissions(task.GetApplicationName())
        # except:
        # 	pass

        # manage task for windows 7
        else:
            if self.disable_redirection:
                wow64 = ctypes.c_long(0)
                ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))

            if os.path.exists(self.task_directory):
                for root, dirs, files in os.walk(self.task_directory):
                    for f in files:

                        xml_file = os.path.join(root, f)
                        try:
                            tree = ElementTree(file=xml_file)
                        except Exception:
                            continue

                        command = ''
                        arguments = ''
                        userid = ''
                        groupid = ''
                        runlevel = ''

                        xmlroot = tree.getroot()
                        for xml in xmlroot:
                            # get task information (date, author)
                            # in RegistrationInfo tag

                            # get triggers information (launch at boot, etc.)
                            # in Triggers tag

                            # get user information
                            if 'principals' in xml.tag.lower():
                                for child in xml.getchildren():
                                    if 'principal' in child.tag.lower():
                                        for principal in child.getchildren():
                                            if 'userid' in principal.tag.lower():
                                                userid = principal.text
                                            elif 'groupid' in principal.tag.lower():
                                                groupid = principal.text
                                            elif 'runlevel' in principal.tag.lower():
                                                runlevel = principal.text

                            # get all execution information (executable and arguments)
                            if 'actions' in xml.tag.lower():
                                for child in xml.getchildren():
                                    if 'exec' in child.tag.lower():
                                        for execution in child.getchildren():
                                            if 'command' in execution.tag.lower():
                                                if execution.text:
                                                    command = os.path.expandvars(execution.text)
                                            elif 'arguments' in execution.tag.lower():
                                                if execution.text:
                                                    arguments = os.path.expandvars(execution.text)

                        full_path = '%s %s' % (str(command), str(arguments))
                        full_path = full_path.strip()

                        if full_path:  # and runlevel != 'LeastPrivilege':
                            t = Taskscheduler()
                            t.name = f
                            t.full_path = full_path
                            t.paths = get_path_info(t.full_path)

                            if userid == 'S-1-5-18':
                                t.userid = 'LocalSystem'
                            else:
                                t.userid = userid

                            t.groupid = groupid
                            t.runlevel = runlevel

                            # append the tasks to the main tasklist
                            tasks.append(t)

            if self.disable_redirection:
                ctypes.windll.kernel32.Wow64EnableWow64FsRedirection(wow64)

        return tasks
