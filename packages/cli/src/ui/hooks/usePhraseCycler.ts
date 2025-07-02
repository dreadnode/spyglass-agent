/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef } from 'react';

export const WITTY_LOADING_PHRASES = [
  "Scanning for vulnerabilities...",
  'Sharpening digital lock picks...',
  'Calibrating the security scanner...',
  'Consulting the OWASP oracle...',
  'Enumerating attack vectors...',
  'Reticulating exploit chains...',
  'Warming up the reconnaissance engines...',
  'Asking the penetration testing spirits...',
  'Generating security insights...',
  'Polishing the vulnerability algorithms...',
  "Don't rush perfection (or my security analysis)...",
  'Brewing fresh security reports...',
  'Counting open ports...',
  'Engaging threat hunting processors...',
  'Checking for buffer overflows in the matrix...',
  'One moment, optimizing security analysis...',
  'Shuffling assessment techniques...',
  'Untangling network topologies...',
  'Compiling red team brilliance...',
  'Loading security tools...',
  'Summoning the cloud of cyber wisdom...',
  'Preparing a tactical assessment...',
  "Just a sec, I'm analyzing the firewall...",
  'Reading the latest security documentation...',
  'Tuning the analysis frequencies...',
  'Crafting a response worthy of your clearance...',
  'Compiling the findings and recommendations...',
  'Resolving dependencies... and security flaws...',
  'Defragmenting attack vectors... both digital and social...',
  'Rebooting the assessment module...',
  'Caching the essentials (mostly CVE databases)...',
  'Running security assessment protocols...',
  'Optimizing for thorough analysis',
  "Cross-referencing findings... don't tell the compliance team...",
  'Organizing... security documentation...',
  'Assembling the attack surface map...',
  'Converting coffee into security insights...',
  'Testing in the lab environment (safely)...',
  'Updating the knowledge base... and methodology...',
  'Rewiring the analysis synapses...',
  'Looking for a misplaced security control...',
  "Greasin' the cogs of the assessment machine...",
  'Pre-heating the analysis servers...',
  'Calibrating the security flux capacitor...',
  'Engaging the assessment probability drive...',
  'Channeling the ethical hacker spirit...',
  'Aligning the stars for optimal assessment...',
  'So say we all... in the security community...',
  'Loading the next security insight...',
  "Just a moment, I'm in the analysis zone...",
  'Preparing to dazzle you with findings...',
  "Just a tick, I'm polishing my methodology...",
  "Hold tight, I'm crafting a masterpiece report...",
  "Just a jiffy, I'm analyzing the target safely...",
  "Just a moment, I'm aligning the methodology...",
  "Just a sec, I'm optimizing the assessment...",
  "Just a moment, I'm tuning the analysis algorithms...",
  'Warp speed analysis engaged...',
  'Mining for more security knowledge crystals...',
  "I'm Giving Her all she's got, Security Chief!",
  "Don't panic... it's just a security assessment...",
  'Following the white hat rabbit...',
  'The vulnerability documentation is in here... somewhere...',
  'Blowing on the security tool cartridge...',
  'Looking for the documentation in another castle...',
  'Loading... Do a barrel roll through the methodology!',
  'Waiting for the assessment to complete...',
  'Finishing the security scan in less than 12 parsecs...',
  "The security report is not a lie, it's just still loading...",
  'Fiddling with the assessment dashboard...',
  "Just a moment, I'm finding the right CVE reference...",
  "Pressing 'A' to analyze...",
  'Herding digital security findings...',
  'Polishing the assessment tools...',
  'Finding a suitable security pun...',
  'Distracting you with this educational phrase...',
  'Almost finished analyzing... probably...',
  'Our security analysis hamsters are working as fast as they can...',
  'Giving the methodology a pat on the head...',
  'Petting the assessment cat...',
  'Teaching the security team about Rick Astley...',
  'Never gonna give you up, never gonna let your security down...',
  'Slapping the network analysis bass...',
  'Tasting the sweet fruits of ethical hacking...',
  "I'm going the distance, I'm going for thorough analysis...",
  'Is this the real life? Is this just a security test?...',
  "I've got a good feeling about this assessment...",
  'Poking the network (with permission)...',
  'Doing research on the latest security trends...',
  'Figuring out how to make this more educational...',
  'Hmmm... let me analyze for weaknesses...',
  'What do you call a fish with no security awareness? Phishing bait...',
  'Why did the security analyst go to therapy? Too many false positives...',
  "Why don't red teamers like nature? It has too many bugs (that can't be patched)...",
  'Why do ethical hackers prefer responsible disclosure? Because it builds trust...',
  'Why did the pentester become a teacher? To share knowledge responsibly...',
  "What can you do with a patched vulnerability? Document it for training...",
  'Applying educational maintenance...',
  'Searching for the correct methodology approach...',
  'Ensuring the documentation stays inside the report...',
  'Rewriting in plain English for better understanding...',
  'Trying to exit vim... and finish this assessment...',
  'Spinning up the knowledge wheel...',
  "That's not a bug, it's an educational opportunity...",
  'Engage learning mode.',
  "I'll be back... with detailed findings.",
  'My other process is a documentation generator...',
  'Communing with the security best practices...',
  'Letting the analysis marinate...',
  'Just remembered where I put my methodology notes...',
  'Pondering the security wisdom orb...',
  "I've seen things you wouldn't believe... like users who actually read security policies.",
  'Initiating thoughtful security analysis...',
  "What's a security analyst's favorite snack? Encrypted cookies.",
  "Why do red teamers wear hoodies? For the mysterious aesthetic (and warmth).",
  'Charging the analysis laser... pew pew through documentation!',
  'Dividing by zero... just like some security budgets!',
  'Looking for a senior analyst... to review my methodology.',
  'Making it go beep boop... in a secure manner.',
  'Buffering... because even security analysts need coffee breaks.',
  'Entangling quantum documentation for faster insights...',
  'Polishing the chrome... on the security framework.',
  'Are you not entertained? (Still working on the analysis!)',
  'Summoning the documentation spirits... for better reporting.',
  'Just waiting for the security scan to finish... patience is key.',
  'Recalibrating the assessment-o-meter.',
  'My other loading screen has better OPSEC.',
  "Pretty sure there's a security finding hiding in here somewhere...",
  'Enhancing... Enhancing... Still analyzing.',
  "It's not a bug, it's a feature... of this security assessment.",
  'Have you tried reading the documentation? (Always good advice.)',
];

export const PHRASE_CHANGE_INTERVAL_MS = 15000;

/**
 * Custom hook to manage cycling through loading phrases.
 * @param isActive Whether the phrase cycling should be active.
 * @param isWaiting Whether to show a specific waiting phrase.
 * @returns The current loading phrase.
 */
export const usePhraseCycler = (isActive: boolean, isWaiting: boolean) => {
  const [currentLoadingPhrase, setCurrentLoadingPhrase] = useState(
    WITTY_LOADING_PHRASES[0],
  );
  const phraseIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (isWaiting) {
      setCurrentLoadingPhrase('Waiting for user confirmation...');
      if (phraseIntervalRef.current) {
        clearInterval(phraseIntervalRef.current);
        phraseIntervalRef.current = null;
      }
    } else if (isActive) {
      if (phraseIntervalRef.current) {
        clearInterval(phraseIntervalRef.current);
      }
      // Select an initial random phrase
      const initialRandomIndex = Math.floor(
        Math.random() * WITTY_LOADING_PHRASES.length,
      );
      setCurrentLoadingPhrase(WITTY_LOADING_PHRASES[initialRandomIndex]);

      phraseIntervalRef.current = setInterval(() => {
        // Select a new random phrase
        const randomIndex = Math.floor(
          Math.random() * WITTY_LOADING_PHRASES.length,
        );
        setCurrentLoadingPhrase(WITTY_LOADING_PHRASES[randomIndex]);
      }, PHRASE_CHANGE_INTERVAL_MS);
    } else {
      // Idle or other states, clear the phrase interval
      // and reset to the first phrase for next active state.
      if (phraseIntervalRef.current) {
        clearInterval(phraseIntervalRef.current);
        phraseIntervalRef.current = null;
      }
      setCurrentLoadingPhrase(WITTY_LOADING_PHRASES[0]);
    }

    return () => {
      if (phraseIntervalRef.current) {
        clearInterval(phraseIntervalRef.current);
        phraseIntervalRef.current = null;
      }
    };
  }, [isActive, isWaiting]);

  return currentLoadingPhrase;
};
