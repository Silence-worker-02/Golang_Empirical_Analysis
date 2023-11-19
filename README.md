# Empirical Analysis of Vulnerabilities Life Cycle in Golang Ecosystem.
This repository is provide the scripts and technical documentation of Empirical Analysis of Vulnerabilities Life Cycle in Golang Ecosystem.

note: These files' functions should be executed sequentially.
1. Run index_crawl.py to gather Golang Index information.
2. Utilize vulnerability_mongodb.py to create the vulnerability database.
3. Execute generate_safe_range.py to determine the safe range of vulnerabilities.
4. Fetch the dependency relation from the Bigquery Database.
5. Run generate_vul_dependents.py to identify repositories for analysis.
6. Use download_libs_vul.py to download vulnerable repositories.
7. Utilize get_exactly_patch_time.py to pinpoint the exact fix time for impacted modules.
Note: In research_questions.py, each RQ and Figure introduce functions to retrieve corresponding data.
8. Run research_questions.py to analyze the generated data, covering analysis for rq1-rq4."


Because of the limit of large files, we only provide dataset here(https://drive.google.com/file/d/1T9aqAmDJlQO3ytWzGv3cT0oxL3yOB69Y/view?usp=sharing, https://drive.google.com/file/d/1d4MR5YtfzBUgeWoGzTELLIeNYSdV8OJ6/view?usp=sharing, https://drive.google.com/file/d/1dHUZ6p01d8CBdAbNrIR3qqArIyne7QiA/view?usp=sharing, https://drive.google.com/file/d/1q--I7Ysz14v834M7EeQIaF7ewM3u1A_m/view?usp=sharing, https://drive.google.com/file/d/1to6i9pmhwUsw0PnvABdC2oa5EEJLa8Mf/view?usp=sharing)
