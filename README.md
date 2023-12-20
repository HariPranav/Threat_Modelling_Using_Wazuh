# Threat_Modelling_Using_Wazuh


# Working with Wazuh :

What is Wazuh and what are some of the experiments we can perform on Wazuh :


# Setting up agents on Wazuh:

From the screenshot below we need to open our terminal and type:

```$ipconfig
```

This command gives the IP address of the machine where our Wazuh server is running. Then based on this information, we need to login into the Wazuh dashboard as shown in the right side of the screenshot and click on "Agents" and click on "Deploy new Agent". Then under we need to choose the platform where we need to deploy the agent for example if we have a windows machine or if we have an ubuntu based machine the commands will vary. In our case we have another instance of ubuntu in our VM. 
As per the screenshot we need to input the IP address of the Wazuh machine into the "Assign a Server Address" section.


![wazuh_agent_install_ubuntu.png]()

Then we need to run the following commands inside our new ubuntu machine as given below:

![wazuh_agent_install_ubuntu.png](image.png)

Once all the steps have been completed successfully we can see in the Wazuh dashboard that it is getting the logs from the Wazuh dashboard. Next we are going to set up file integrity monitoring on the Ubuntu machine. Here we enable certain functionalities in which if the user downloads a file in the ubuntu machine and makes any changes to it then, the logs can be seen on the Wazuh dashboard and appropriate action can be taken on it.

Then we need to navigate to the directory on our Ubuntu machine where the agent has been installed: 

```nano /var/etc/ossec/ossec.conf
```
Then add the following lines under the **syscheck** section as shown in the screenshot below:

```<directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
```
![modifying_file_integrity_monitoring.png]()

Next we need to restart the Wazuh agent using the command: 

```sudo systemctl restart wazuh-agent
```
Now in the ubuntu machine we need to create a new file in the root directory then, add contents into it and then after some time delete the file. Once this is done we can switch back to the Wazuh machine and explore the logs. In the screenshot below on the Ubuntu machine we have done the same as given below:

![creating_new_files_modifying_contents]()

Switching back to the Wazuh dashboard we need to navigate to Security - > Events and checking the same we can see the **Rule Id:553, 550 and 554** have details about file integrity monitoring.

![wazuh_agent_file_integritymonitoring]()

