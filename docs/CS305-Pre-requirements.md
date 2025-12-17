# Presentation Requirements

Each group will have at most **8 minutes** to present their work. It is NOT necessary to use the full time.

You will need to prepare **simple slides** for your presentation.

## Slides Content

For saving time, please keep your slides simple and concise.

You may include the following information in your slides:

### Introduction to your design

Describe the working flow of your work, and any important components, for instance:

* Classes you add
* Data structure
* Your header (if you extend the standard header)
* TCP timeout related determination, implementation and behavior
* Other content related to RDT implementation.
* Other important parts
* ...

### Congestion Control check

* Show your **cwnd record plot**, and describe your plot (when are slow start, congestion avoidance, packet loss... or any other congestion control algorithms you implemented).

### Concurrency check

* Show your **concurrency visualization plot** (automatically generated after running concurrency test).

### Crash check

* Generate and show a concurrency plot after running crash test by:

    ```bash
    python3 test/concurrency_visualizer.py logs/peer1.log
    ```

### Optimize check (If Any)

* Discuss what you have done to optimize the performance of your code.
* Show evidence (if applicable). **Just for example**:
  * If you implement **fast recovery**, you should show us a different cwnd plot.
  * If you implement **SR**, show us your corresponding peer log.

### Contribution Rate

If your contributions **are not equally distributed**, mark the ratio of your contributions in your slides.

### Note

Our goal is assess your progress, so please be honest about your implementation. Claiming features that are not actually functional will be considered cheating.

## Others

### Time registration

Register your presentation time in the online form (see Blackboard announcement). Try to select separately to avoid situations where there are too many people at a particular time.

### Attendance

All group members are required to be present unless there are special circumstances. If you have a valid reason for absence, please explain it to the instructor and follow the formal leave application process.

### Submission

After your presentation, you should submit your presentation slides (as a PowerPoint or PDF (preferred) file) like `gxx_pre.pdf`. (xx is your group id).

### Contribution Calculation

Your individual score will be calculated by

$$s_i=\min(S(1+1.1(w_i−\frac{1}{N})),120)$$

where $s_i$ is the $i$th member's score, $S$ is your group raw points, $w_i$ is the $i$-th member's contribution rate, $N$ is the number of students in your team. Note that $\sum w_i=1$

