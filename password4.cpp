// password4.cpp
//
// Create unique password for a given identifier from predefined common seed
//
// Building:
//
//   g++ -O3 -Wall -Wextra -std=c++11 -g -o password4 password4.cpp
//
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <x86intrin.h>

// 1,296 most memorable and distinct words from
// https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt
const int WORDLIST_LENGTH = 1296;
static const char* wordlist[WORDLIST_LENGTH] = 
{"acid","acorn","acre","acts","afar","affix"
,"aged","agent","agile","aging","agony","ahead"
,"aide","aids","aim","ajar","alarm","alias"
,"alibi","alien","alike","alive","aloe","aloft"
,"aloha","alone","amend","amino","ample","amuse"
,"angel","anger","angle","ankle","apple","april"
,"apron","aqua","area","arena","argue","arise"
,"armed","armor","army","aroma","array","arson"
,"art","ashen","ashes","atlas","atom","attic"
,"audio","avert","avoid","awake","award","awoke"
,"axis","bacon","badge","bagel","baggy","baked"
,"baker","balmy","banjo","barge","barn","bash"
,"basil","bask","batch","bath","baton","bats"
,"blade","blank","blast","blaze","bleak","blend"
,"bless","blimp","blink","bloat","blob","blog"
,"blot","blunt","blurt","blush","boast","boat"
,"body","boil","bok","bolt","boned","boney"
,"bonus","bony","book","booth","boots","boss"
,"botch","both","boxer","breed","bribe","brick"
,"bride","brim","bring","brink","brisk","broad"
,"broil","broke","brook","broom","brush","buck"
,"bud","buggy","bulge","bulk","bully","bunch"
,"bunny","bunt","bush","bust","busy","buzz"
,"cable","cache","cadet","cage","cake","calm"
,"cameo","canal","candy","cane","canon","cape"
,"card","cargo","carol","carry","carve","case"
,"cash","cause","cedar","chain","chair","chant"
,"chaos","charm","chase","cheek","cheer","chef"
,"chess","chest","chew","chief","chili","chill"
,"chip","chomp","chop","chow","chuck","chump"
,"chunk","churn","chute","cider","cinch","city"
,"civic","civil","clad","claim","clamp","clap"
,"clash","clasp","class","claw","clay","clean"
,"clear","cleat","cleft","clerk","click","cling"
,"clink","clip","cloak","clock","clone","cloth"
,"cloud","clump","coach","coast","coat","cod"
,"coil","coke","cola","cold","colt","coma"
,"come","comic","comma","cone","cope","copy"
,"coral","cork","cost","cot","couch","cough"
,"cover","cozy","craft","cramp","crane","crank"
,"crate","crave","crawl","crazy","creme","crepe"
,"crept","crib","cried","crisp","crook","crop"
,"cross","crowd","crown","crumb","crush","crust"
,"cub","cult","cupid","cure","curl","curry"
,"curse","curve","curvy","cushy","cut","cycle"
,"dab","dad","daily","dairy","daisy","dance"
,"dandy","darn","dart","dash","data","date"
,"dawn","deaf","deal","dean","debit","debt"
,"debug","decaf","decal","decay","deck","decor"
,"decoy","deed","delay","denim","dense","dent"
,"depth","derby","desk","dial","diary","dice"
,"dig","dill","dime","dimly","diner","dingy"
,"disco","dish","disk","ditch","ditzy","dizzy"
,"dock","dodge","doing","doll","dome","donor"
,"donut","dose","dot","dove","down","dowry"
,"doze","drab","drama","drank","draw","dress"
,"dried","drift","drill","drive","drone","droop"
,"drove","drown","drum","dry","duck","duct"
,"dude","dug","duke","duo","dusk","dust"
,"duty","dwarf","dwell","eagle","early","earth"
,"easel","east","eaten","eats","ebay","ebony"
,"ebook","echo","edge","eel","eject","elbow"
,"elder","elf","elk","elm","elope","elude"
,"elves","email","emit","empty","emu","enter"
,"entry","envoy","equal","erase","error","erupt"
,"essay","etch","evade","even","evict","evil"
,"evoke","exact","exit","fable","faced","fact"
,"fade","fall","false","fancy","fang","fax"
,"feast","feed","femur","fence","fend","ferry"
,"fetal","fetch","fever","fiber","fifth","fifty"
,"film","filth","final","finch","fit","five"
,"flag","flaky","flame","flap","flask","fled"
,"flick","fling","flint","flip","flirt","float"
,"flock","flop","floss","flyer","foam","foe"
,"fog","foil","folic","folk","food","fool"
,"found","fox","foyer","frail","frame","fray"
,"fresh","fried","frill","frisk","from","front"
,"frost","froth","frown","froze","fruit","gag"
,"gains","gala","game","gap","gas","gave"
,"gear","gecko","geek","gem","genre","gift"
,"gig","gills","given","giver","glad","glass"
,"glide","gloss","glove","glow","glue","goal"
,"going","golf","gong","good","gooey","goofy"
,"gore","gown","grab","grain","grant","grape"
,"graph","grasp","grass","grave","gravy","gray"
,"green","greet","grew","grid","grief","grill"
,"grip","grit","groom","grope","growl","grub"
,"grunt","guide","gulf","gulp","gummy","guru"
,"gush","gut","guy","habit","half","halo"
,"halt","happy","harm","hash","hasty","hatch"
,"hate","haven","hazel","hazy","heap","heat"
,"heave","hedge","hefty","help","herbs","hers"
,"hub","hug","hula","hull","human","humid"
,"hump","hung","hunk","hunt","hurry","hurt"
,"hush","hut","ice","icing","icon","icy"
,"igloo","image","ion","iron","islam","issue"
,"item","ivory","ivy","jab","jam","jaws"
,"jazz","jeep","jelly","jet","jiffy","job"
,"jog","jolly","jolt","jot","joy","judge"
,"juice","juicy","july","jumbo","jump","junky"
,"juror","jury","keep","keg","kept","kick"
,"kilt","king","kite","kitty","kiwi","knee"
,"knelt","koala","kung","ladle","lady","lair"
,"lake","lance","land","lapel","large","lash"
,"lasso","last","latch","late","lazy","left"
,"legal","lemon","lend","lens","lent","level"
,"lever","lid","life","lift","lilac","lily"
,"limb","limes","line","lint","lion","lip"
,"list","lived","liver","lunar","lunch","lung"
,"lurch","lure","lurk","lying","lyric","mace"
,"maker","malt","mama","mango","manor","many"
,"map","march","mardi","marry","mash","match"
,"mate","math","moan","mocha","moist","mold"
,"mom","moody","mop","morse","most","motor"
,"motto","mount","mouse","mousy","mouth","move"
,"movie","mower","mud","mug","mulch","mule"
,"mull","mumbo","mummy","mural","muse","music"
,"musky","mute","nacho","nag","nail","name"
,"nanny","nap","navy","near","neat","neon"
,"nerd","nest","net","next","niece","ninth"
,"nutty","oak","oasis","oat","ocean","oil"
,"old","olive","omen","onion","only","ooze"
,"opal","open","opera","opt","otter","ouch"
,"ounce","outer","oval","oven","owl","ozone"
,"pace","pagan","pager","palm","panda","panic"
,"pants","panty","paper","park","party","pasta"
,"patch","path","patio","payer","pecan","penny"
,"pep","perch","perky","perm","pest","petal"
,"petri","petty","photo","plank","plant","plaza"
,"plead","plot","plow","pluck","plug","plus"
,"poach","pod","poem","poet","pogo","point"
,"poise","poker","polar","polio","polka","polo"
,"pond","pony","poppy","pork","poser","pouch"
,"pound","pout","power","prank","press","print"
,"prior","prism","prize","probe","prong","proof"
,"props","prude","prune","pry","pug","pull"
,"pulp","pulse","puma","punch","punk","pupil"
,"puppy","purr","purse","push","putt","quack"
,"quake","query","quiet","quill","quilt","quit"
,"quota","quote","rabid","race","rack","radar"
,"radio","raft","rage","raid","rail","rake"
,"rally","ramp","ranch","range","rank","rant"
,"rash","raven","reach","react","ream","rebel"
,"recap","relax","relay","relic","remix","repay"
,"repel","reply","rerun","reset","rhyme","rice"
,"rich","ride","rigid","rigor","rinse","riot"
,"ripen","rise","risk","ritzy","rival","river"
,"roast","robe","robin","rock","rogue","roman"
,"romp","rope","rover","royal","ruby","rug"
,"ruin","rule","runny","rush","rust","rut"
,"sadly","sage","said","saint","salad","salon"
,"salsa","salt","same","sandy","santa","satin"
,"sauna","saved","savor","sax","say","scale"
,"scam","scan","scare","scarf","scary","scoff"
,"scold","scoop","scoot","scope","score","scorn"
,"scout","scowl","scrap","scrub","scuba","scuff"
,"sect","sedan","self","send","sepia","serve"
,"set","seven","shack","shade","shady","shaft"
,"shaky","sham","shape","share","sharp","shed"
,"sheep","sheet","shelf","shell","shine","shiny"
,"ship","shirt","shock","shop","shore","shout"
,"shove","shown","showy","shred","shrug","shun"
,"shush","shut","shy","sift","silk","silly"
,"silo","sip","siren","sixth","size","skate"
,"skew","skid","skier","skies","skip","skirt"
,"skit","sky","slab","slack","slain","slam"
,"slang","slash","slate","slaw","sled","sleek"
,"sleep","sleet","slept","slice","slick","slimy"
,"sling","slip","slit","slob","slot","slug"
,"slum","slurp","slush","small","smash","smell"
,"smile","smirk","smog","snack","snap","snare"
,"snarl","sneak","sneer","sniff","snore","snort"
,"snout","snowy","snub","snuff","speak","speed"
,"spend","spent","spew","spied","spill","spiny"
,"spoil","spoke","spoof","spool","spoon","sport"
,"spot","spout","spray","spree","spur","squad"
,"squat","squid","stack","staff","stage","stain"
,"stall","stamp","stand","stank","stark","start"
,"stash","state","stays","steam","steep","stem"
,"step","stew","stick","sting","stir","stock"
,"stole","stomp","stony","stood","stool","stoop"
,"stop","storm","stout","stove","straw","stray"
,"strut","stuck","stud","stuff","stump","stung"
,"stunt","suds","sugar","sulk","surf","sushi"
,"swab","swan","swarm","sway","swear","sweat"
,"sweep","swell","swept","swim","swing","swipe"
,"swirl","swoop","swore","syrup","tacky","taco"
,"tag","take","tall","talon","tamer","tank"
,"taper","taps","tarot","tart","task","taste"
,"tasty","taunt","thank","thaw","theft","theme"
,"thigh","thing","think","thong","thorn","those"
,"throb","thud","thumb","thump","thus","tiara"
,"tidal","tidy","tiger","tile","tilt","tint"
,"tiny","trace","track","trade","train","trait"
,"trap","trash","tray","treat","tree","trek"
,"trend","trial","tribe","trick","trio","trout"
,"truce","truck","trump","trunk","try","tug"
,"tulip","tummy","turf","tusk","tutor","tutu"
,"tux","tweak","tweet","twice","twine","twins"
,"twirl","twist","uncle","uncut","undo","unify"
,"union","unit","untie","upon","upper","urban"
,"used","user","usher","utter","value","vapor"
,"vegan","venue","verse","vest","veto","vice"
,"video","view","viral","virus","visa","visor"
,"vixen","vocal","voice","void","volt","voter"
,"vowel","wad","wafer","wager","wages","wagon"
,"wake","walk","wand","wasp","watch","water"
,"wavy","wheat","whiff","whole","whoop","wick"
,"widen","widow","width","wife","wifi","wilt"
,"wimp","wind","wing","wink","wipe","wired"
,"wiry","wise","wish","wispy","wok","wolf"
,"womb","wool","woozy","word","work","worry"
,"wound","woven","wrath","wreck","wrist","xerox"
,"yahoo","yam","yard","year","yeast","yelp"
,"yield","yoyo","yodel","yoga","yoyo","yummy"
,"zebra","zero","zesty","zippy","zone","zoom"};

static inline void
speck_round(uint64_t& x, uint64_t& y, const uint64_t k)
{
  x = __rorq(x, 8);
  x += y;
  x ^= k;
  y = __rolq(y, 3);
  y ^= x;
}

static void 
speck_encrypt( uint64_t data[2]
             , const uint64_t key[4]
             )
{
  uint64_t a = key[0];
  uint64_t bcd[3] = {key[1], key[2], key[3]};
  for (unsigned i = 0; i < 34; i++) {
    speck_round(data[1], data[0], a);
    speck_round(bcd[i % 3], a, i);
  }
}

static uint64_t 
bytes_to_uint64(const uint8_t bytes[], unsigned length)
{
  uint64_t w = 0;
  for (unsigned i = 0, shift = 0; i < length; i++, shift += 8) {
    w |= ((uint64_t)bytes[i] << shift);
  }
  return w;
}

int main(int argc, char** argv)
{
  if (argc != 2) { // No arguments, do a self-check and show usage
    const uint64_t key[4]       = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL
                                  , 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL };
    const uint64_t plaintext[2] = { 0x202e72656e6f6f70ULL, 0x65736f6874206e49ULL };
    const uint64_t expected[2]  = { 0x4eeeb48d9c188f43ULL, 0x4109010405c0f53eULL };
    uint64_t observed[2]; observed[0] = plaintext[0]; observed[1] = plaintext[1];
    speck_encrypt(observed, key);
    if ( expected[0] != observed[0] 
      || expected[1] != observed[1]
       ) {
      std::cerr << "speck_encrypt() self-test failed\n" 
                << "Expected 0x" << std::hex << expected[0] << ", 0x" << expected[1] << "\n"
                << "Observed 0x" << observed[0] << ", 0x" << observed[1] << "\n";
       return 1;
    }
    std::cerr << "Usage:\n\n\tpassword4 john.doe@example.com\n\n"
      "Creates base58-encoded password by encrypting FNV-1a hash of given identifier\n"
      "with Speck128/256 on the key passed in environmental variable CRYPTOLOCKER_PASSWORD.\n";
    return 0;
  }

  // Read the secret seed for use as encryption key
  const char* seed = std::getenv("CRYPTOLOCKER_PASSWORD");
  std::string seed_str;
  if (!seed) {
    std::cerr << "Enter seed (32 chars max): ";
    std::getline (std::cin, seed_str);
    seed = seed_str.c_str();
  }
  uint64_t k[4] = { 0 };
  {
    unsigned bytes_left = strlen(seed);
    for (unsigned i = 0; i < 4; i++, bytes_left -= 8) {
      k[i] = bytes_to_uint64((uint8_t*)(seed + i * 8), bytes_left > 8 ? 8 : bytes_left);
      if (bytes_left <= 8) break;
    }
  }

  // Calculate FNV-1a hash of the input. Hash function does not have to be 
  // cryptographically strong because potential attacker cannot choose the input.
  // We just want to use all of the input and spread it across 128 bits to 
  // avoid collisions (same output for different inputs).
  uint64_t d[2] = { 0 };
  __uint128_t fnv_prime = 1; // FNV prime is 2**88 + 0x13b
  fnv_prime <<= 88;
  fnv_prime |= 0x13b;
  __uint128_t hash = fnv_prime;
  for (unsigned char* p = (unsigned char*)(argv[1]); *p; p++) {
    hash ^= *p;
    hash *= fnv_prime;
  }
  d[0] = (uint64_t)hash;
  hash >>= 64;
  d[1] = (uint64_t)hash;

  // Encrypt hashed input a thousand times
  for (unsigned i = 0; i < 1000; i++) {
    speck_encrypt(d, k);
  }

  // Password is three words from the wordlist and one three digit number
  std::string buffer;
  for (int i = 0; i < 3; i++) {
    buffer.append(wordlist[d[1] % WORDLIST_LENGTH]);
    d[1] /= WORDLIST_LENGTH;
    buffer.append(1, '-');
  }
  const char* digits = "0123456789";
  for (int i = 0; i < 3; i++) {
    buffer.append(1, digits[d[0] % 10]);
    d[0] /= 10;
  }
  buffer[0] = std::toupper(buffer[0]);
  std::cout << buffer << "\n";
  return 0;
}
