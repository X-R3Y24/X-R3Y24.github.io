### **Intro**

| Category | Info |
|------|---------|
| CTF | BSidesSF CTF 2026 |
| Author | Symmetric |
| Category | Crypto (black-box cryptanalysis) |  
| Difficulty | I’d say medium-hard as it required both the black-box RE skills and the knowledge of dodecahedron symmetry group |
| Timeline | Around 36 hours of solo work (around 24 excluding food, sleep and irl stuff) |
| Link to the challenge | [Dodecacrypt](https://github.com/BSidesSF/ctf-2026-release/blob/main/dodecacrypt/challenge/dodeca_flag.png) |
| Cipher | A novel (beautiful and very visually pleasing) cipher based on a symmetry group of a dodecahedron |
| Primitive | There isn’t really a primitive per se. That’s a black-box encryption oracle problem which needs to be reversed engineered. It’s just not IND-CPA secure, but that’s how it’s meant to be |
| What was provided | a screenshot of a encrypted flag and the link to the server - https://dodecacrypt-949351df.challenges.bsidessf.net/. |
| Goal | Guess the encrypted message by reverse engineering the cipher using the black-box endpoint |

![Photo](/assets/img/posts/dodecacrypt/flag.png){: .w-50 .center}
### **Step 1 - cryptanalysis + getting key letters:**  
So how did I approach the problem? When you first enter the site you see this: 

![Photo](/assets/img/posts/dodecacrypt/homepage.png){: .w-50 .center}

The first thing I noticed was a weird length of a message to length of a ciphertext ratio. 20 to 14? Was it this even? Ok, whatever. Anyway, let’s check the behavior when faced with a long message consisting of a single char: 

![Photo](/assets/img/posts/dodecacrypt/longA.png){: .w-50 .center}

As we can see there isn’t a simple pattern in this ct. Then, let’s check the key. This is where the magic starts. No matter what you’ll type the key is always 12 chars long. And it only allows letters (the whole cipher uses upper case letters and when given a lower case letter it just uses to_upper on it. Hence, I’ll just type letters everywhere instead of upper case letters), 12? In a dodecahedron? I wonder why?. I then started encrypting a single char message with a single char key. As you imagine, every letter has its own color corresponding to it. And to make sure that every position in a key corresponds to a particular position on a big dode (yeah the reference to the big doge meme [big doge](https://ih1.redbubble.net/image.1286047921.7977/st,small,507x507-pad,600x600,f8f8f8.jpg)). One thing I also noticed is that each dodecahedron influences all of the dodecahedrons that follow, but not the ones that precede it. 

<div style="display:flex; gap:8px; justify-content:center">
  <img src="/assets/img/posts/dodecacrypt/keyA.png" width="100%">
  <img src="/assets/img/posts/dodecacrypt/keyB.png" width="100%">
</div>
![Photo](/assets/img/posts/dodecacrypt/keyAB.png){: .w-50 .center}

Knowing all of this let’s find which letters create the key. We’ll find it out by extracting them from the flag. Let’s notice that there are 12 distinct colors in our ct meaning we have 12 different letters in a key. The letters forming the key are: 

![Photo](/assets/img/posts/dodecacrypt/letters.png)

### **Step 2 - remembering icosahedral groups and finding boundaries:**

Ok, part one is done. We have the letters of the key. Which means we have “only” 12! possible keys. Now for the cipher. Let’s run a script sending every char to the oracle and checking if the ct has been created. It turns out that only letters from englando alphabet are valid. But…. wait a minute. Let’s check back the screenshot from the initial state. EXAMPLE_MESSAGE_HERE. You see? "\_"!!!!! It wasn’t accepted as a first sign, but it’s valid further? Let’s run the script back, but check the 2nd char now. Now we see that underscore is a valid sign too, but for some reason not as a 1st char. Weird. Very weird. The next thing that came to my mind was to check when does the 2nd dode appear. The last one die message is DK and the first two die message is DL. Hmmmmm 3 * 27 + 12 = 93. Another weird number. But look D_ corresponds to one die while DZ to two. If so we can assume a standard lexicographical order, but with underscore being the lowest value instead of the highest like in ASCII? Then we have "\_" = 0, "A" = 1, … "Z" = 26 gives base 27. Then our equation looks like this: 4 * 27 + 12 = 120. Yeah that’s definitely correct, the "\_" being the lowest char flipped the narration and made everything stick. Before that I had a bug where A2 was AL + "\_" instead of "\_" + AL. That cost me like 6 hours as the results didn’t make any sense. Instead of 120 for a 2nd die I was getting 92. Explained why below.

```python
AL: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2: str = "_" + AL

def msg_to_num(s: str) -> int:
    if len(s) == 1:
        return AL.index(s[0])
    n: int = 27**(len(s) - 1)
    n += AL.index(s[0]) * (27**(len(s) - 1))
    for i in range(1, len(s)):
        c: int = 0 if s[i] == '_' else AL.index(s[i])
        n += c * (27**(len(s) - 1 - i))
    return n

def num_to_msg(n: int) -> str:
    if n < 26:
        return AL[n]
    length: int = 2
    while (27**length) - 1 <= n:
        length += 1
    rem: int = n - (27**(length - 1))
    chars: List[str] = []
    div: int = 27**(length - 1)
    chars.append(AL[rem // div])
    rem = rem % div
    for i in range(length - 2, -1, -1):
        div = 27**i
        chars.append(A2[rem // div])
        rem = rem % div
    return "".join(chars)
```

![Photo](/assets/img/posts/dodecacrypt/encoding.png)

For those who are unfamiliar with dodecahedron symmetry group – 120 is the size of such group. Meaning that every dodecahedron with no two matching sides can be put on a table in 120 different ways. 

```python
# Generate full group by closure
all_perms = set()
for v, p in sigma_known.items():
    all_perms.add(tuple(p))
all_perms.add(tuple(inv_map))

changed = True
while changed:
    changed = False
    new = set()
    for p in all_perms:
        for q in all_perms:
            r = tuple(compose(list(p), list(q)))
            if r not in all_perms and r not in new:
                new.add(r)
                changed = True
    all_perms.update(new)

print(f"Symmetry group size: {len(all_perms)}")
assert len(all_perms) == 120, "Expected 120 elements!"
APL = sorted(all_perms)
```

Here is an interactive dodecahedron so you can rotate it yourself and have a lot of fun!

<iframe src="/assets/img/posts/dodecacrypt/dodecacrypt_interactive.html" width="100%" height="520" frameborder="0" style="border:none;"></iframe>

Think of it like a coin. Coin either faces up with heads or tails (skip the edge stand weirdo). Dodecahedron has heads, tails, hands, knees and whatever makes it up to 120. In order to confirm when the next is needed let’s run a quick script that will calculate the powers of 120 up to 26 (the length of the ct) and check if incrementing it by one adds a new dode. 

```python
for k in range(1, 27):
    boundary = 120**k
    last_k = boundary - 1
    
    msg_last = num_to_msg(last_k)
    msg_first = num_to_msg(boundary)
    
    res_last = enc(msg_last)
    res_first = enc(msg_first)
    
    if not res_last or not res_first:
        print(f"k ={k}: API Error")
        break
        
    count_last = res_last.get("count", 0)
    count_first = res_first.get("count", 0)
    
    print(f"k = {k:2}: last = {last_k} \"{msg_last}\" -> {count_last} die | "
            f"first = {boundary} \"{msg_first}\" -> {count_first} die")
```

By the way shame on me since I then wrote a script that iterates through every possible message and checks those boundaries in the brutal way. For personal defence I was very hungry so I wrote that script quickly, ate the lunch and came back to a solved problem. I’ll spare you the code this time. 

### **Step 3 - the actual key group**

This is where it gets tough. We need to find the right symmetry group to which our cts’ key belongs. After all 120 is strictly less than 12!. We’ll do it by a constraint satisfaction over the ct. One die gives as 6 sides for sure and 6 sides hidden. To find THE group we need dodes to show at least 11 sides (we know the letters so 12th one is free). Why are 6 sides enough? Well our flag has 26 dodecas. 26 * 6 = 156 constraints over 12 element permutation. Much more than enough. So we will use a basic pruning tree over the ct. For each die we try all 120 rotations and check if it’s consistent across dice. If yes, check the next die. If no dump this possibility (prune this branch). The one that’s left is the right one This is the script I used:

```python
def die_char_constraints(die_idx, perm_idx):
    """
    For a given die showing flag_vis[die_idx], assuming the die uses
    permutation APL[perm_idx], compute what key positions must hold
    which letters.
    
    Returns dict {key_position: letter} or None if invalid.
    """
    perm = APL[perm_idx]
    obs = flag_vis[die_idx]
    constraints = {}
    for i, face_idx in enumerate(VISIBLE):
        key_pos = perm[face_idx]
        letter = obs[i]
        if letter not in KEY_LETTERS:
            return None
        if key_pos in constraints:
            if constraints[key_pos] != letter:
                return None  # conflict
        constraints[key_pos] = letter
    # Check no two positions assigned same letter
    vals = list(constraints.values())
    if len(vals) != len(set(vals)):
        return None
    return constraints

def compatible(c1, c2):
    """Check if two constraint dicts can coexist in a single key."""
    pos_to_letter = {}
    letter_to_pos = {}
    for c in [c1, c2]:
        for pos, letter in c.items():
            if pos in pos_to_letter and pos_to_letter[pos] != letter:
                return False
            if letter in letter_to_pos and letter_to_pos[letter] != pos:
                return False
            pos_to_letter[pos] = letter
            letter_to_pos[letter] = pos
    return True
```
The script returns a 120 element group of keys that are able to create a ciphertext identical to our flag. In other words, each key returned by the script has a corresponding message that encrypted by said key will 
become our flag.

### **Step 4 - recovering the message(s)**

Now that we finally know the correct group let’s decipher the flag. 
There are two ways. 
- Street smart - let’s notice that one of the keys says: BYLOGRAPHICS which is the only really readable message. Use it as a key and find the message using binsearch – after all we have a total order over the set {0, 1, …, 26} we can use programmers favourite weapon which is of course… binary search. It will print our flag and we are good.
- The real one – the first one works only if we are lucky – that means only in CTF scenario, not for random chars. This solution works. Period. The algorithm is as follows. You take any key from the symmetry group. You bin search the message and then you just calculate all remaining 118 messages. But wait 120 – 1 = 119 not 118, so why 118? 120 minus 1 (neutral element, produces only 25 dice) minus 1 (the key you used for the binary search) = 118 remaining.  Well every group needs such special element called a neutral element. Think of it like a zero sign. 0123 is a perfectly fine string. However when used as a number we skip the zero as it doesn’t bring any difference to the number. So one of our 120 keys is a zero in that group and degenerates to 25 die. The rest 118 messages we find just by rotating our dodecahedron. So we write a quick script that will rotate the dodecahedron for us and print all the 119 messages. The one we are looking for is the readable one.

**Solution:**  
- Key: BYLOGRAPHICS
- Plaintext: HI_IM_SYMMETRIC_AND_THIS_IS_YOUR_FLAG  

**Hi Symmetric! Thanks for your flag (and genuinely one of the best riddles ever)!** 

### **Epilogue** 
That was my first live CTF and I’ve picked this one as a stand out challenge of the CTFs (I’ve participated in two simultaneously). Not only wasn’t it just finding a one variable that breaks RSA/ECC, but it was completely novel. It involved a knowledge about the dodecahedrons, but not something not Googlable in 5 minutes. It required some cryptanalyst skills, but not something you need to work on for years. But it was engaging, fun and visually astonishing. Kudos to Symmetric work coming up with such a beauty! Here is the link to his CTFs:  
[2025](https://github.com/BSidesSF/ctf-2025-release/blob/main/block-cipher/challenge/flag.png)  
[2023](https://github.com/BSidesSF/ctf-2023-release/blob/main/alien/distfiles/flag.png)  
[2022](https://github.com/BSidesSF/ctf-2022-release/blob/main/septoglyph/challenge/flag.png)  
If you are afraid that you won’t be able to solve any challs at the beginning. Chill out. I’ve started self learning crypto six months ago and solved 4 challs. The most important part however for me personally isn’t just solving it, but having fun while doing it. Even if you don’t manage to solve a single problem, trust me you’ll have a lot of fun. And if you do, you’ll be proud the entire month. Like I’m now. It’s not an exam, it’s just a fun way to spend time. Try it

**Lessons learned:**
- Never take your ASCII codes for granted,  
- Always check your underscores,  
- The joy after solving the problem is much bigger than the will to throw your laptop outside the window when failing,  
- How to spell dodecahedron.  

Link to all scripts I’ve used: [scripts](https://github.com/X-R3Y24/CTF-solves/tree/main/Crypto/BSidesSF-CTF-2026/Dodecacrypt)  
**“I X-R3Y your ciphers… Crying? It’s called CRYptography after all”**