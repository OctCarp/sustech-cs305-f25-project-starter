## CS 305 Fall 2025 Grading (Code & Script Testing)

Congratulations on completing the Project. Although the setup process was a bit complex, most groups did a great job. We believe you now have a deeper understanding of the TCP mechanism.

The **Script Testing** part is worth **80 points**:

- **40 pts**: Basic Tests
- **30 pts**: 2 Public Advanced Tests + 1 Hidden Test
- **10 pts**: Performance Bonus

**Note**: The remaining points are for the Congestion Control Demo (20 pts) and Presentation (10 pts), making the maximum total score 110.

### Submission Policy

- **Multiple Submitters**: For groups where multiple members submitted code (not recommended though), we graded the **latest** submission within the group.
- **Late Submissions**: Unless you specified which non-late version to use in advance, we treated late submissions as late and applied the penalty discount according to the course policy.

### Testing

Considering the importance of robustness, we ran the tests **3 times** for each case.

#### Basic Tests (40 pts)

- If you passed the test at least once, you get full marks.

#### Comprehensive Tests (Public) (Total 20 pts)

For each test case:

- **10 pts**: Perfect pass (passed 3/3 times).
- **7 pts**: Failed at least once (but passed at least once).
- **4 pts**: Passed at least once (minimum requirement).

#### Hidden Test (10 pts)

- **10 pts**: Perfect pass.
- **5 pts**: Passed at least once.

### Performance Ranking (Bonus 10 pts)

We treat performance as an extra requirement. The ranking policy is as follows:

- **Metric**: We use the **fastest** time recorded among the successful runs.
- **Test Cases**: Calculated based on `test_06_adv2` and `test_07` (Hidden).
- **Robustness Penalty**: If your code failed during any of the 3 runs, your time for that test is multiplied by **1.5**.
- **Final Score**: Sum of the calculated times for both tests.

Example:

Your fastest times are 100s (for test 06) and 70s (for test 07).

However, you did not pass test 07 perfectly (there was a failure in one of the runs).

Your final ranking time = $100 + 70 \times 1.5 = 205s$.

### Grade Disputes (Appeal)

You can check your script scores with the TA during your presentation, but please be mindful of the time.

**Note:** The error logs for the Advanced/Hidden tests usually only show "Timeout". We do not accept appeals regarding the Comprehensive Tests unless there is a significant deviation from your own estimation.

If you have any other questions regarding the **Code & Script Testing scores**, please contact **TA Chunhui Xu** via QQ / WeCom (企业微信) / Email before **18:00 this Friday**. Requests sent after this deadline will not be processed.

------

### Test Platform Specifications

- **Python**: 3.12.9
- **CPU**: Intel(R) Xeon(R) Gold 5320 CPU @ 2.20GHz
- **RAM Size**: 256 GB
- **SSD**: SAMSUNG MZQL2960HCJR-00A07
- **System**: Ubuntu 20.04.1 LTS
