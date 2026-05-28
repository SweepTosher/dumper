# Umamusume event outcome predictor thingamajig   
event results are sent to the client before the button is even clicked. this tool makes em visible.       

# Install
```bash
git clone https://github.com/SweepTosher/dumper
pip install -r requirements.txt
```
---
also uh there's no existing database for ts so its gonna map itself as u play. but at first ur gonna see a bunch of "not mapped"     

compares the before and after of all ur values so it might be inaccurate at first (if ur energy is at 5 it's gonna map a event that -20 energy as -5 energy for example)     

it's take the most extreme as the database updates itself. for example -5 energy is gonna get overwritten by -20 and so on. (same goes for positives)    

^^^ also means that "a hint for growth" or any other event that gives variable stats/skills is gonna display "+ every stat/skill" after a while but u should be able to understand whats going on behind the scene.

<img width="1810" height="1080" alt="image" src="https://github.com/user-attachments/assets/c668329e-176a-4002-857c-377b7101ec18" />    


even without being mapped even idx usually means bad outcome apart from race and training fail events (and some edge cases but yeah)   
