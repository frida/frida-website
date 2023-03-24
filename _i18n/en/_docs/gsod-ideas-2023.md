# Planning for an updated Frida documentation

_Planning how to make the Frida documentation better_

This document examines the current state of the Frida documentation and discusses how to make it better.

## Current state of the documentation and support

### Current availability of documentation

1. [Official Frida documentation (frida.re/docs)](https://frida.re/docs/)  TODO: Describe what's currently in the documentation.
1. [Learn Frida and Frida Handbook](https://learnfrida.info/), by [Fernando Diaz](https://learnfrida.info/about_faq/).
The site has online documentation (HTML) and the book is accessible liberally from the same site and also the NowSecure Academy site.
1. _Other locations?_

### User support 

1. Users can get [Frida support on Telegram](https://frida.re/contact/). There are currently 2720 members. _Frida OffTopic_ has 457 members.
1. Users can get [Frida support on IRC/Freenode #frida](https://frida.re/contact/). Less than ten people on the channel, probably inactive due to the split between Freenode and Libera.
1. There is a #frida channel on Libera Chat. There were 13 users on that channel when I visited. The existence of the channel is not listed on the frida.re website yet.
1. [Github Issues on github/frida/frida](https://github.com/frida/frida/issues). The Github Issues are (ab)used as a help venue.
1. [Discord Frida Server](https://discord.gg/J7VCWhZQ5N). 180 members, 40 online when I last visited (EU timezone).

## Rationale (for the update of the Frida documentation)

Every free/open-source project should make known and understood what it does. This enhances the viability and may bring more contributors to the project.

The most difficult part of maintaining a project is the software development aspect. The documentation and the growing of the community are easier and should not be neglected.

## Types of audience for this documentation

The documentation should cater the following groups of users

1. Power users that are experienced with other computer-related tasks and want to expand to Frida.
   The documentation should relate to their prior knowledge when explaining Frida. 
1. Users with experience in Frida that want to consult the documentation as a quick reminder for some task.
   The documentation should not be exclusively in screencasts but in text form for easy copy-pasting of complex commands. The commands should be easy to identify. When you select a line, it should not select the Unix prompt.
1. Users with little computer experience but willing to make the effort to learn. 
   They should get a good understanding what Frida does, be able to successfully set up Frida, and perform at least an easy task. 
1. Users are are interested in the applications of Frida but will ask someone else to take up the task/job.
   They should be able to have a good understanding what Frida does and be able to evaluate roughly the difficulty of the task/job.

## Purposes of documentation

* Avoid repeated questions on the support channels.
* Show best practices for common tasks.
* Cover initial successful installation on a variety of operating systems. Include Troubleshooting. Include simple verification tasks that the installation was successful. 
* The documentation should be accessible, by the search engines. The majority of users search on a search engine. Commons searches should direct to the documentation. It will also be picked up by those AI search engines.

## What should go in the new documentation

* Discussion article: What is really Frida? Type of _Access to the address space of a running software_. Use _Cheat Engine_ as example. Cheat Engine does read/write/set on the data segment to alter the number of lives or coins. Newer Cheat Engine [also does code inject, with assembly!](https://wiki.cheatengine.org/index.php?title=Tutorials:Auto_Assembler:Injection_full).
* Discussion article: What is really Frida? Practical explanation with Greasemonkey/Tampermonkey/Violentmonkey. Actually, [Violentmonkey](https://github.com/violentmonkey/violentmonkey), which is the one with active development.
* Installation, general instructions for Windows/Linux/OSX, individual articles for each major OS version, with Troubleshooting section and verification examples that it was installed successfully. The individual articles are there so they can be picked by search engines and used by new users.
* Reference article: What are those different packages in the assets, https://github.com/frida/frida/releases (i.e. _code devkit_, _gum devkit_,...)
* Android: how to setup Frida on a rooted phone
* Android: how to inject the Gadget in the APK, how to get the APK from the phone in the first place. [Use apk.sh](https://github.com/ax/apk.sh).
* Code Share: Explain how to use https://codeshare.frida.re/, how to contribute, 
* Desktop: Show how to use Frida on the three major desktops.
* _TODO_

## TODO

* Add documentation on https://github.com/frida/frida/issues when you create a new Issue. Instruct how to collect better information for a bug report. Should say that it is not a support venue.
* Use forum software? Perhaps not discord (walled garden, inaccessible by search engines). [Managed like StackExchange](https://area51.stackexchange.com/) or [self-hosted like Discourse](https://github.com/discourse/discourse).


## Organization proposal for Google Season of Docs

[General instructions on creating an organization proposal](https://developers.google.com/season-of-docs/docs/organization-application-hints).

We follow the template at https://developers.google.com/season-of-docs/docs/org-proposal-template 

Proposal starts now:

## Update Frida's website documentation

### About your organization

[Frida](https://frida.re) (current version 16.0.11, first release in 2013) is a wxWindows Library Licence-licenced software toolkit for dynamic code instrumentation. It attaches to running software and gives you access to the execution flow and data. It lets you inject your own code written in Javascript so that you can modify how the software is running. Frida is commonly used in the computer security field for reverse engineering, such as in [this case by Google Project Zero](https://googleprojectzero.blogspot.com/2022/01/zooming-in-on-zero-click-exploits.html). Frida is the go-to tool for reverse-engineering mobile apps for both Android and iOS. In addition, Frida is also used in software testing, debugging, and software development. Frida currently supports nine operating systems and three architecture families (Intel, ARM, MIPS). Finally, Frida is the most popular software in its field.

### About your project

The [official Frida documentation](https://frida.re/docs/) needs to be restructured and expanded. It has been written by advanced users and is too terse for new users. New users end up asking questions on the project's github issues (around ten questions per week). There is a Telegram channel with 2730 users but it is difficult to offer support; any answers given, are difficult to be discovered by the next person asking the same question.

There is a need to create a friction log, help identify knownledge gaps and provide troubleshooting documentation. The use-cases should include the set up of Frida on a number of the supported operating systems and provide steps to verify that the setup is working. Discussion documents should be provided that explain what Frida does, for audiences of different levels of technical experience and background.

Frida is one of the tools that security researchers use. There is an ecosystem of such open-source security tools, including AFL++ (security fuzzying), ghidra (decompilation). A security researcher would use either one or a mix of those tools to accomplish a task. By improving the documentation, Frida will have a better position in supporting the ecosystem and growing its own community. 

### Your project’s scope

The Frida project will:

* Audit the existing documentation and create a friction log for the three top use cases (setting up Frida for different operating systems, setting up Frida with the Frida gadget, and common tasks with Frida).
* Using the friction log as a guide for understanding the gaps in the documentation, create updated documentation for the top use cases.
* Create a quick “cheat sheet” to help new users to install and use Frida quickly and effectively.
* Incorporate feedback from documentation testers (volunteers in the project) and the wider Frida community.
* Work with the release team to update the documentation on the Frida site, and to create a process for keeping the documentation in sync with the update tool going forward.
* Create issue templates for Github Issues so that users are redirected to the official documentation and support site if they ask support questions. Add templates for reporting bugs and feature requests.
* Go through the 1300 Github issues and tag appropriately those that are support requests. Use as input in the documentation.
* Include documentation of the different types of assets in the Github Releases and how they should be used.
* Incorporate https://codeshare.frida.re/ in the Frida documentation.

Work that is out-of-scope for this project:

* This project will not produce detailed documentation for code contributions to Frida. 

We have a strong technical writing candidate for this project, and we estimate that this work will take six months to complete. @simos has committed to supporting the project.

### Measuring your project’s success

We would consider the project successful if, after publication of the new documentation:

* 90% of the new user questions are covered.
* The number of Github issues that are actually support requests drop to two per week.

### Timeline

The project itself will take approximately six months to complete. Once the tech writer is hired, we'll spend a month on tech writer orientation, then move onto the audit and friction log, and spend last few months focusing on creating the documentation.

|Dates 	               |Action Items                                               |
|-----------------------|-----------------------------------------------------------|
|May 	                  |Orientation                                                |
|June - July    	      |Audit existing documentation and create friction log       |
|August - October     	|Create documentation                                       |
|November 	            |Project completion                                         |

### Project budget

|Budget Item 	                   |Budgeted (USD)                |Actual (USD)      | Notes    |
|---------------------------------|------------------------------|------------------|----------|
|Technical Writer                 |$12,000                       | $12,000          |          |
|Volunteer Stipends (3 x $500)    |$1,500                        | $13,500          | For volunteers that will be closely providing information and/or reviewing deliverables |
|T-shirts for volunteers       	 |$200                          | $13,700          | Printing and delivery to volunteers with documentation contribution |
TOTAL                             |                              | $13,700          |
