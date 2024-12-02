---
title: Designing a Secure Device-to-Device File Transfer Mechanism
event:  CS 6262 Project Session
event_url: https://gatech.edu

location: Georgia Tech
address:
  street: 
  city: Atlanta
  country: United States

summary: Secure, reliable, and fast transfer of files across the Internet is a problem attempted to be solved through many application-layer protocols. In this paper, we aim to design a secure, reliable, open-design, and performant file transfer protocol that is inspired by the WebRTC protocol stack. Traditionally, transferring files involves a publicly exposed (available on the public network) third-party server that serves the uploaded files to the receiver. Here, the third-party server has to bear the storage and bandwidth cost to transfer the files between the two parties. We propose a protocol that uses a relay server to relay the files from the client to the server. A relay server has several advantages over a regular file-hosting server. Firstly, a relay server does not retain the uploaded files, it simply relays them. Secondly, a relay server has a full-duplex communication channel and therefore the receiver is not required to wait for the sender to upload the files completely. In this paper, we study available file transfer approaches and their known flaws. We propose our idea and compare our stack with WebRTC. Finally, we perform empirical analysis and, benchmark our device-to-device transfer approach along with other available options including WebRTC. 

# Talk start and end times.
#   End time can optionally be hidden by prefixing the line with `#`.
date: "2021-04-24T11:00:00Z"
date_end: ""
all_day: false

# Schedule page publish date (NOT talk date).
publishDate: ""

authors: ["Chaitanya Rahalkar","Anushka Virgaonkar"]
tags: ["file-transfer","p2p"]

# Is this a featured talk? (true/false)
featured: false

image:
  caption: 'Image credit: [**Unsplash**](https://unsplash.com/photos/bzdhc5b3Bxs)'
  focal_point: Right

links: 
url_code: ""
url_pdf: ""
url_slides: "https://git.io/cs6262"
url_video: ""

# Markdown Slides (optional).
#   Associate this talk with Markdown slides.
#   Simply enter your slide deck's filename without extension.
#   E.g. `slides = "example-slides"` references `content/slides/example-slides.md`.
#   Otherwise, set `slides = ""`.
slides: ""

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []

# Enable math on this page?
math: true
---

Secure, reliable, and fast transfer of files across the Internet is a problem attempted to be solved through many application-layer protocols. In this paper, we aim to design a secure, reliable, open-design, and performant file transfer protocol that is inspired by the WebRTC protocol stack. Traditionally, transferring files involves a publicly exposed (available on the public network) third-party server that serves the uploaded files to the receiver. Here, the third-party server has to bear the storage and bandwidth cost to transfer the files between the two parties. We propose a protocol that uses a relay server to relay the files from the client to the server. A relay server has several advantages over a regular file-hosting server. Firstly, a relay server does not retain the uploaded files, it simply relays them. Secondly, a relay server has a full-duplex communication channel and therefore the receiver is not required to wait for the sender to upload the files completely. In this paper, we study available file transfer approaches and their known flaws. We propose our idea and compare our stack with WebRTC. Finally, we perform empirical analysis and, benchmark our device-to-device transfer approach along with other available options including WebRTC. Get a copy of the slides [here](https://git.io/cs6262)!