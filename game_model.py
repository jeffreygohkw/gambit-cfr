import gambit
import sys
import os
import csv
import random
import time
import matplotlib.pyplot as plt
import pickle


def fraction(numerator, denominator):
    return gambit.Rational(numerator, denominator)

 # CVSS metrics
max_exploitability_score = round(8.22 * 0.85 * 0.77 * 0.85 * 0.85, 1)
max_exploitability_score_frac = fraction(int(round(max_exploitability_score * 10, 0)), 10)
print("__________")
max_impact_score = round(6.42 * (1 - pow((1 - 0.56), 3)), 1) 
max_impact_score_frac = fraction(int(round(max_impact_score * 10, 0)), 10)
print("Max Explotability Score: " + str(max_exploitability_score))
print("Max Impact Score: " + str(max_impact_score))

class CVE():
    def __init__(self, name, impact, exploitability, DOS):
        self.name = name
        self.impact = impact
        self.exploitability = exploitability
        self.DOS = DOS

    def get_exploitability(self):
        return self.exploitability
    
    def get_impact(self):
        return self.impact
    
    def get_exploitability_frac(self):
        print(type(self.exploitability))
        print(type(max_exploitability_score_frac))
        return fraction(gambit.Rational(self.exploitability), max_exploitability_score_frac)
                       
    def get_impact_frac(self):
        return int(round(self.impact / max_impact_score * 100, 0))
    
    def get_name(self):
        return self.name
    
    def is_DOS(self):
        return self.DOS
            
class BPEdited:
    
    def __init__(self, bp, g):
        self.bp = bp.copy()   
        self.game = g
        
    def get_bp(self):
        return self.bp
    
    def set_D_infoset0_svr1_prob(self, list_of_probs):
        num_actions = len(self.game.root.children[0].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for action_idx in range(num_actions):
            self.bp[self.game.root.infoset.members[0].children[0].infoset][action_idx] = list_of_probs[action_idx]
    
    def set_D_infoset0_svr2_prob(self, list_of_probs):
        num_actions = len(self.game.root.children[1].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for action_idx in range(num_actions):
            self.bp[self.game.root.infoset.members[0].children[1].infoset][action_idx] = list_of_probs[action_idx]
    
    
    def set_A_infoset0_prob(self, list_of_probs):
        num_actions = len(self.game.root.children[0].children[0].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for action_idx in range(num_actions):
            self.bp[self.game.root.children[0].children[0].infoset][action_idx] = list_of_probs[action_idx]

    def set_A_infoset1_prob(self, list_of_probs):
        num_actions = len(self.game.root.children[0].children[0].children[0].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for member_idx in range(len(self.game.root.children[0].children[0].infoset.members)):
            for child_idx in range(len(self.game.root.children[0].children[0].children)):
                for action_idx in range(num_actions):
                    if not self.game.root.children[0].children[0].infoset.members[member_idx].children[child_idx].is_terminal:
                        self.bp[self.game.root.children[0].children[0].infoset.members[member_idx].children[child_idx].infoset][action_idx] = list_of_probs[action_idx]
    
        
    def set_A_infoset_subtree(self, list_of_probs, subtree_root):
        num_actions = len(subtree_root.infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for action_idx in range(num_actions):
            self.bp[subtree_root.infoset][action_idx] = list_of_probs[action_idx]
                
    def set_D_infoset_subtree_sd(self, list_of_probs, subtree_root):
        num_actions = len(subtree_root.children[0].children[0].children[0].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for p in range(len(subtree_root.infoset.actions)): #The 3 exploits
            if not subtree_root.children[p].children[0].is_terminal:
                for action_idx in range(num_actions):
                    self.bp[subtree_root.children[p].children[0].children[0].infoset][action_idx] = list_of_probs[action_idx]
                       
    def set_D_infoset_subtree_nd(self, list_of_probs, subtree_root):
        num_actions = len(subtree_root.children[0].children[0].children[1].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for p in range(len(subtree_root.infoset.actions)): #The 3 exploits
            if not subtree_root.children[p].children[0].is_terminal:
                for action_idx in range(num_actions):
                    self.bp[subtree_root.children[p].children[0].children[1].infoset][action_idx] = list_of_probs[action_idx]
                    self.bp[subtree_root.children[p].children[1].children[1].infoset][action_idx] = list_of_probs[action_idx]
        #attacker quits
        self.bp[subtree_root.children[len(subtree_root.infoset.actions) - 1].infoset][action_idx] = list_of_probs[action_idx]
                        
    def set_D_infoset_subtree_fd(self, list_of_probs, subtree_root):
        num_actions = len(subtree_root.children[0].children[1].children[0].infoset.actions)
        if not len(list_of_probs) == num_actions:
            raise Exception("A list of " + str(num_actions) + " probabilities must be input")
        elif sum(list_of_probs) != 1:
            raise Exception("Probabilities must sum to 1")
        for i in range(len(list_of_probs)):
            if list_of_probs[i] < 0 or list_of_probs[i] > 1:
                raise Exception("Probabilities must be between 0 and 1")
        for p in range(len(subtree_root.infoset.actions)): #The 3 exploits
            if not subtree_root.children[p].children[0].is_terminal:
                for action_idx in range(num_actions):
                    self.bp[subtree_root.children[p].children[1].children[0].infoset][action_idx] = list_of_probs[action_idx]
    
    
    
class GameTree:
    def __init__(self, file_name):
        
        assert type(file_name) == str, "File name of GameTree must be a string"
        self.file_name = file_name
        
        self.subtrees = []
        
        self.regret_table = {}
        self.strategy_table = {}
        self.m = [{}, {}]
        
        # C_infosetinit, wrong setup payoffs, 
        # svr1 importance values, svr2 importance values, 
        # subtree detection modifiers, 
        # subtree terminal node payoffs modifiers
        # layer_multiplier values
        self.default_values = [[3, 10], [-100, -85, -95, -80], 
                               [10, 25, 15, 30], [20, 35, 25, 40], 
                               [58, 10, 100, 42, 10, 100, 1812, 100, 10000, 8188, 100, 10000], 
                               [40, 7.0/10.0, 1.0, 1.0/10.0, 4.0/10.0], 
                               [1.5, 1]]
        
        self.g = gambit.Game.new_tree() # Game tree for Extensive Form Game
        
        self.g.title = 'cyber_game'
        
        #print('No of players: {}'.format(len(self.g.players)))
        
        chance_player = self.g.players.chance # Chance player is there by default.
        
        #print('Chance player is {}'.format(chance_player))
        
        # Adding Attacker and Defender.
        self.g.players.add('A')
        self.g.players.add('D')
        
        #print('No of players: {}'.format(len(self.g.players)))
        
        #print(self.g.players[0])
        #print(self.g.players[1])
        
        self.A = self.g.players[0]
        self.D = self.g.players[1]
        self.C = chance_player
        
        self.attacker_private_chance_nodes = []
        self.defender_private_chance_nodes = []
        self.public_chance_nodes = []
        
        #For CFR
        self.terminal_node_vectors = []
        
        self.terminal_nodes = []
        
        # CVSS metrics
        self.max_exploitability_score = round(8.22 * 0.85 * 0.77 * 0.85 * 0.85, 1)
        self.max_exploitability_score_frac = fraction(int(round(self.max_exploitability_score * 10, 0)), 10)
        #print("__________")
        self.max_impact_score = round(6.42 * (1 - pow((1 - 0.56), 3)), 1) 
        self.max_impact_score_frac = fraction(int(round(self.max_impact_score * 10, 0)), 10)
        #print("Max Explotability Score: " + str(self.max_exploitability_score))
        #print("Max Impact Score: " + str(self.max_impact_score))

        self.p1 = CVE('CVE-2018-0553', 5.2, 2.2, False) #CVE-2018-0553, CVSS score 7.4
        self.p2 = CVE('CVE-2016-10451', 5.9, 1.8, False) #CVE-2016-10451, CVSS score 7.8
        self.p3 = CVE('CVE-2016-10464', 3.6, 3.9, True) #CVE-2016-10464, CVSS score 7.5
        
    def write_file(self):
        serialised_form = self.g.write('efg')
        f = open(self.file_name +'.efg', 'w')
        f.writelines(serialised_form)
        f.close()
 

    def set_payoff(self, node, attacker_payoff):
        node.outcome = self.g.outcomes.add()
        node.outcome[0] = int(attacker_payoff)
        node.outcome[1] = -int(attacker_payoff)
        if node not in self.terminal_nodes:    
            self.terminal_nodes.append(node)
            
        # =============================================================================
    def build_subtree(self, root_node, importance_value, layer_multiplier, values, name = '_'):
        
        root_node.actions[0].label = 'p1'
        root_node.actions[1].label = 'p2'
        root_node.actions[2].label = 'p3'
        root_node.actions[3].label = 'quit'
        # Attacker attacks server 1
        node_in_A_infoset1_s1 = root_node.members[0]
        
        A1_s1_p1 = node_in_A_infoset1_s1.children[0]
        A1_s1_p2 = node_in_A_infoset1_s1.children[1]
        A1_s1_p3 = node_in_A_infoset1_s1.children[2]
        
        D_infoset1_quit = node_in_A_infoset1_s1.children[3].append_move(self.D, 2)
        D_infoset1_quit.label = 'D_infoset1' + name + 'quit_nd'
        #Logically speaking, there are only TWO actions emerging from D_infoset1_s1.
        D_infoset1_quit.actions[0].label = 'b'  # block
        D_infoset1_quit.actions[1].label = 'nb' # no-block
        self.set_payoff(D_infoset1_quit.members[0].children[0], layer_multiplier * (values[1][0] + importance_value)) # defender blocks but there was no exploit
        self.set_payoff(D_infoset1_quit.members[0].children[1], importance_value + layer_multiplier * 10) # defender doesn't block and there was no exploit



        singleton = [D_infoset1_quit.members[0].children[1]] 
        self.terminal_node_vectors.append(singleton)

        # Connect A_infoset1_s1 to C_infoset1_s1_pX.
        C_infoset1_s1_p1 = A1_s1_p1.append_move(self.C, 2)
        C_infoset1_s1_p2 = A1_s1_p2.append_move(self.C, 2)
        C_infoset1_s1_p3 = A1_s1_p3.append_move(self.C, 2)

        def update_C_infoset1_s1_pX(ifs, ifs_label):
            ifs.label = ifs_label
            ifs.actions[0].label = 's'  # successful exploit
            ifs.actions[1].label = 'f' # failed exploit

        update_C_infoset1_s1_pX(C_infoset1_s1_p1, 'C_infoset1' + name + 'p1')
        update_C_infoset1_s1_pX(C_infoset1_s1_p2, 'C_infoset1' + name + 'p2')
        update_C_infoset1_s1_pX(C_infoset1_s1_p3, 'C_infoset1' + name + 'p3')
            
        def assign_success_prob_C_infoset1(ifs, exploit):
            ifs.actions[0].prob = exploit.get_exploitability_frac() # prob of successful exploit 
            ifs.actions[1].prob = 1 - exploit.get_exploitability_frac() # prob of failed exploit
            for node in ifs.members:    
                if exploit.is_DOS():
                    self.public_chance_nodes.append(node)
                else:
                    self.attacker_private_chance_nodes.append(node)
                    
        
        for ifs_idx, ifs in enumerate([C_infoset1_s1_p1, C_infoset1_s1_p2, C_infoset1_s1_p3]):
          if ifs_idx in [0]: #p1
              assign_success_prob_C_infoset1(ifs, self.p1)
          if ifs_idx in [1]: #p2
              assign_success_prob_C_infoset1(ifs, self.p2)
          if ifs_idx in [2]: #p3
              assign_success_prob_C_infoset1(ifs, self.p3)
        
              
        #Detection for p1
        C_infoset2_s1_p1_s = C_infoset1_s1_p1.members[0].children[0].append_move(self.C, 2)  
        C_infoset2_s1_p1_f = C_infoset1_s1_p1.members[0].children[1].append_move(self.C, 2)
        
        C_infoset2_s1_p1_s.label = 'C_infoset2' + name + 'p1_s'
        C_infoset2_s1_p1_s.actions[0].label = 'd' # Detected
        C_infoset2_s1_p1_s.actions[1].label = 'nd' # Not detected
        
        C_infoset2_s1_p1_f.label = 'C_infoset2' + name + 'p1_f'
        C_infoset2_s1_p1_f.actions[0].label = 'd' # Detected
        C_infoset2_s1_p1_f.actions[1].label = 'nd' # Not detected
        
        #Detection for p2
        C_infoset2_s1_p2_s = C_infoset1_s1_p2.members[0].children[0].append_move(self.C, 2)
        C_infoset2_s1_p2_f = C_infoset1_s1_p2.members[0].children[1].append_move(self.C, 2)
        
        C_infoset2_s1_p2_s.label = 'C_infoset2' + name + 'p2_s'
        C_infoset2_s1_p2_s.actions[0].label = 'd' # Detected
        C_infoset2_s1_p2_s.actions[1].label = 'nd' # Not detected
        
        C_infoset2_s1_p2_f.label = 'C_infoset2' + name + 'p2_f'
        C_infoset2_s1_p2_f.actions[0].label = 'd' # Detected
        C_infoset2_s1_p2_f.actions[1].label = 'nd' # Not detected

        #Detection for p3
        C_infoset2_s1_p3_s = C_infoset1_s1_p3.members[0].children[0].append_move(self.C, 2)
        C_infoset2_s1_p3_s.label = 'C_infoset2' + name + 'p3_s'
        C_infoset2_s1_p3_s.actions[0].label = 'd' # Detected
        C_infoset2_s1_p3_s.actions[1].label = 'nd' # Not detected
             
        C_infoset2_s1_p3_f = C_infoset1_s1_p3.members[0].children[1].append_move(self.C, 2)
        C_infoset2_s1_p3_f.label = 'C_infoset2' + name + 'p3_f'
        C_infoset2_s1_p3_f.actions[0].label = 'd' # Detected
        C_infoset2_s1_p3_f.actions[1].label = 'nd' # Not detected
        
        def assign_success_prob_C_infoset2_s(ifs, exploit):
            if ifs == C_infoset2_s1_p3_s: # Special case for DOS, always detectable
                ifs.actions[0].prob = 1
                ifs.actions[1].prob = 0
                self.public_chance_nodes.append(ifs.members[0])
            else:
                ifs.actions[0].prob = min(1, fraction(values[0][0] + int(values[0][1] / layer_multiplier), values[0][2])) # prob of detecting successful exploit 
                ifs.actions[1].prob = max(0, fraction(values[0][3] - int(values[0][4] / layer_multiplier), values[0][5])) # prob of not detecting successful exploit
                for node in ifs.members:
                    self.defender_private_chance_nodes.append(node)

        def assign_success_prob_C_infoset2_f(ifs, exploit):
            ifs.actions[0].prob = max(0, fraction(values[0][6] - int(values[0][7] / layer_multiplier), values[0][8])) # prob of detecting failed exploit, false alarm 
            ifs.actions[1].prob = min(1, fraction(values[0][9] + int(values[0][10] / layer_multiplier), values[0][11])) # prob of not detecting failed exploit
            for node in ifs.members:
                self.defender_private_chance_nodes.append(node)
            
        for ifs_idx, ifs in enumerate([C_infoset1_s1_p1, C_infoset1_s1_p2, C_infoset1_s1_p3]):
            if ifs_idx in [0]: #p1
                exploit = self.p1
            if ifs_idx in [1]: #p2
                exploit = self.p2
            if ifs_idx in [2]: #p3
                exploit = self.p3

            assign_success_prob_C_infoset2_s(ifs.members[0].children[0].infoset, exploit)
            assign_success_prob_C_infoset2_f(ifs.members[0].children[1].infoset, exploit)
            
        # =============================================================================
        D_infoset1_s1_sd = C_infoset2_s1_p1_s.members[0].children[0].append_move(self.D, 2) # sd
        D_infoset1_s1_sd.label = 'D_infoset1' + name + 'sd'
        #Logically speaking, there are only TWO actions emerging from D_infoset1_s1.
        D_infoset1_s1_sd.actions[0].label = 'b'  # block
        D_infoset1_s1_sd.actions[1].label = 'nb' # no-block
    
        D_infoset1_s1_nd = C_infoset2_s1_p1_s.members[0].children[1].append_move(D_infoset1_quit) # snd
        
        D_infoset1_s1_fd = C_infoset2_s1_p1_f.members[0].children[0].append_move(self.D, 2) # fd
        D_infoset1_s1_fd.label = 'D_infoset1' + name + 'fd'
        #Logically speaking, there are only TWO actions emerging from D_infoset1_s1.
        D_infoset1_s1_fd.actions[0].label = 'b'  # block
        D_infoset1_s1_fd.actions[1].label = 'nb' # no-block
        
        # Connect C_infoset1 or C_infoset2 to D_infoset0.
        for C_ifs in [C_infoset1_s1_p1, C_infoset1_s1_p2, C_infoset1_s1_p3]:
            for C_ifs_2 in range(len(C_ifs.members[0].children)):    # Successful or failed exploit
                for C_action in range(len(C_ifs.members[0].children[C_ifs_2].children)): # Detected or undetected exploit
                    if C_ifs.members[0].children[C_ifs_2].children[C_action].is_terminal:
                        if C_action == 0 and C_ifs_2 == 0:  #sd
                            if C_ifs == C_infoset1_s1_p3: #DOS
                                D_infoset1_s1_p3_sd = C_ifs.members[0].children[C_ifs_2].children[C_action].append_move(self.D, 2)
                                D_infoset1_s1_p3_sd.label = 'D_infoset1' + name + 'p3_sd'
                                D_infoset1_s1_p3_sd.actions[0].label = 'b'  # block
                                D_infoset1_s1_p3_sd.actions[1].label = 'nb' # no-block
                            else:
                                C_ifs.members[0].children[C_ifs_2].children[C_action].append_move(D_infoset1_s1_sd)
                        elif C_action == 1:                 #nd
                            C_ifs.members[0].children[C_ifs_2].children[C_action].append_move(D_infoset1_s1_nd)
                        elif C_action == 0 and C_ifs_2 == 1: #fd
                            C_ifs.members[0].children[C_ifs_2].children[C_action].append_move(D_infoset1_s1_fd)
                                                
        def D_infoset1_payoff(n1, n2, n3, n4, importance_value, exploit, layer_multiplier):
            #Defender blocks the attacker
            for node_idx, node in enumerate([n1, n2, n3, n4]):
                self.set_payoff(node.children[0], int(layer_multiplier * (values[1][0] + importance_value)))
                self.set_payoff(node.children[1], importance_value + int(values[1][node_idx + 1] * exploit.get_impact_frac())) #sd

        state = []        
        singleton = []
        
        for C_ifs in [C_infoset1_s1_p1, C_infoset1_s1_p2, C_infoset1_s1_p3]:   
            if C_ifs is C_infoset1_s1_p1:
                exploit = self.p1
            if C_ifs is C_infoset1_s1_p2:
                exploit = self.p2
            if C_ifs is C_infoset1_s1_p3:
                exploit = self.p3
            D_infoset1_payoff(C_ifs.members[0].children[0].children[0], 
                          C_ifs.members[0].children[0].children[1], 
                          C_ifs.members[0].children[1].children[0], 
                          C_ifs.members[0].children[1].children[1],
                          importance_value, exploit, layer_multiplier)
            state.append(C_ifs.members[0].children[0].children[0].children[0])
            state.append(C_ifs.members[0].children[0].children[1].children[0])
            if C_ifs == C_infoset1_s1_p3:
                singleton = [C_ifs.members[0].children[1].children[0].children[0]] 
                self.terminal_node_vectors.append(singleton)
            else:
                state.append(C_ifs.members[0].children[1].children[0].children[0])
            state.append(C_ifs.members[0].children[1].children[1].children[0])

            singleton = [C_ifs.members[0].children[0].children[0].children[1]] 
            self.terminal_node_vectors.append(singleton)
            singleton = [C_ifs.members[0].children[0].children[1].children[1]] 
            self.terminal_node_vectors.append(singleton)
            singleton = [C_ifs.members[0].children[1].children[0].children[1]] 
            self.terminal_node_vectors.append(singleton)
            singleton = [C_ifs.members[0].children[1].children[1].children[1]] 
            self.terminal_node_vectors.append(singleton)
        state.append(D_infoset1_quit.members[len(D_infoset1_quit.members) - 2].children[0])
        self.terminal_node_vectors.append(state)
        
        
    #End of build_subtree

        
    # =============================================================================

    def generate_game_tree(self, *values):
        if list(values) == []:
            values = self.default_values
        else:
            values = values[0]
        root_node = self.g.root # Root node (initially terminal node) is always there by default.
        
        self.defender_private_chance_nodes.append(root_node)
        
        # initial infoset to represent the initial network configuration
        C_infosetinit = root_node.append_move(self.C, 2) # Num of levels server can take
        C_infosetinit.label = 'C_infosetinit'
        
        
        C_infosetinit_actions = C_infosetinit.actions
        
        '''
        for idx in range(len(C_infosetinit_actions)):
            C_infosetinit_actions[idx].label = 'svr' + str(idx + 1) # Importance value of the server
            C_infosetinit_actions[idx].prob = fraction(1, len(C_infosetinit_actions)) # prob of server having each individual value
        '''
        C_infosetinit_actions[0].label = 'svr1' # Importance value of the server
        C_infosetinit_actions[1].label = 'svr2' # Importance value of the server
        
        C_infosetinit_actions[0].prob = fraction(values[0][0], values[0][1]) # prob of server being svr1
        C_infosetinit_actions[1].prob = 1 - fraction(values[0][0], values[0][1]) # prob of server being svr2
        
        # C_infosetinit is a singleton.
        assert len(C_infosetinit.members) == 1, 'C_infosetinit is a singleton.'
        node_in_C_infosetinit = C_infosetinit.members[0]
        
        # =============================================================================
        
        Cinit_svr1 = node_in_C_infosetinit.children[0]
        Cinit_svr2 = node_in_C_infosetinit.children[1]
        
        # Connect Cinit infoset to D_infoset0_sx
        D_infoset0_svr1 = Cinit_svr1.append_move(self.D, 4)  # Num of levels honeypot can take * number of setups
        D_infoset0_svr2 = Cinit_svr2.append_move(self.D, 4)
        
        
        def update_D_infoset0_svrX(ifs, ifs_label):
            ifs.label = ifs_label
            ifs.actions[0].label = 'hp1_setup1' # honeypot disguised as server of importance 1
            ifs.actions[1].label = 'hp2_setup1' # honeypot disguised as server of importance 2
            ifs.actions[2].label = 'hp1_setup2' # honeypot disguised as server of importance 1
            ifs.actions[3].label = 'hp2_setup2' # honeypot disguised as server of importance 2
            
        update_D_infoset0_svrX(D_infoset0_svr1, 'D_infoset0_svr1')
        update_D_infoset0_svrX(D_infoset0_svr2, 'D_infoset0_svr2')
        print('g.is_perfect_recall at Cinit: {}'.format(self.g.is_perfect_recall))
        
        # =============================================================================
        # Server 1, HP 1, Setup 1
        A_infoset0 = D_infoset0_svr1.members[0].children[0].append_move(self.A, 2)
        A_infoset0.label = 'A_infoset0'
        
        A_infoset0_actions = A_infoset0.actions
        
        A_infoset0_actions[0].label = 'setup1' # attacker chooses to attack with setup 1 in mind
        A_infoset0_actions[1].label = 'setup2' # attacker chooses to attack with setup 2 inmind
        
        # Add the other attacker nodes into A_infoset0
        for svr in range(len(C_infosetinit.members[0].children)):
            for c in range(len(D_infoset0_svr1.members[0].children)):
                if svr == 0 and c == 0:
                    continue
                node_in_C_infosetinit.children[svr].infoset.members[0].children[c].append_move(A_infoset0)
        
        node_in_A_infoset0_svr1_hp1_setup1 = A_infoset0.members[0]
        node_in_A_infoset0_svr1_hp2_setup1 = A_infoset0.members[1]
        node_in_A_infoset0_svr1_hp1_setup2 = A_infoset0.members[2]
        node_in_A_infoset0_svr1_hp2_setup2 = A_infoset0.members[3]
        node_in_A_infoset0_svr2_hp1_setup1 = A_infoset0.members[4]
        node_in_A_infoset0_svr2_hp2_setup1 = A_infoset0.members[5]
        node_in_A_infoset0_svr2_hp1_setup2 = A_infoset0.members[6]
        node_in_A_infoset0_svr2_hp2_setup2 = A_infoset0.members[7]
        '''
        print('node_in_A_infoset0: {}'.format(node_in_A_infoset0))
        print('node_in_A_infoset0.children: {}'.format(node_in_A_infoset0.children))
        '''
        
        # Server 1
        A0_svr1_hp1_setup1_setup1 = node_in_A_infoset0_svr1_hp1_setup1.children[0]
        A0_svr1_hp1_setup1_setup2 = node_in_A_infoset0_svr1_hp1_setup1.children[1]
        
        A0_svr1_hp2_setup1_setup1 = node_in_A_infoset0_svr1_hp2_setup1.children[0]
        A0_svr1_hp2_setup1_setup2 = node_in_A_infoset0_svr1_hp2_setup1.children[1]
        
        A0_svr1_hp1_setup2_setup1 = node_in_A_infoset0_svr1_hp1_setup2.children[0]
        A0_svr1_hp1_setup2_setup2 = node_in_A_infoset0_svr1_hp1_setup2.children[1]
        
        A0_svr1_hp2_setup2_setup1 = node_in_A_infoset0_svr1_hp2_setup2.children[0]
        A0_svr1_hp2_setup2_setup2 = node_in_A_infoset0_svr1_hp2_setup2.children[1]
        
        # Server 2
        A0_svr2_hp1_setup1_setup1 = node_in_A_infoset0_svr2_hp1_setup1.children[0]
        A0_svr2_hp1_setup1_setup2 = node_in_A_infoset0_svr2_hp1_setup1.children[1]
        
        A0_svr2_hp2_setup1_setup1 = node_in_A_infoset0_svr2_hp2_setup1.children[0]
        A0_svr2_hp2_setup1_setup2 = node_in_A_infoset0_svr2_hp2_setup1.children[1]
        
        A0_svr2_hp1_setup2_setup1 = node_in_A_infoset0_svr2_hp1_setup2.children[0]
        A0_svr2_hp1_setup2_setup2 = node_in_A_infoset0_svr2_hp1_setup2.children[1]
        
        A0_svr2_hp2_setup2_setup1 = node_in_A_infoset0_svr2_hp2_setup2.children[0]
        A0_svr2_hp2_setup2_setup2 = node_in_A_infoset0_svr2_hp2_setup2.children[1]
        
        #==============================================================================
        A_infoset1_svr1_hp1_setup1_setup1 = A0_svr1_hp1_setup1_setup1.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr1_hp1_setup1_setup2, values[1][0]) # Attacker attacks a honeypot    
        singleton = [A0_svr1_hp1_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)

        
        A_infoset1_svr1_hp2_setup1_setup1 = A0_svr1_hp2_setup1_setup1.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr1_hp2_setup1_setup2, values[1][1]) # Attacker attacks a honeypot
        singleton = [A0_svr1_hp2_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)

        
        self.set_payoff(A0_svr1_hp1_setup2_setup1, values[1][2]) # Attacker attacks a honeypot
        A_infoset1_svr1_hp1_setup2_setup2 = A0_svr1_hp1_setup2_setup2.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr1_hp1_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)


        self.set_payoff(A0_svr1_hp2_setup2_setup1, values[1][3]) # Attacker attacks a honeypot
        A_infoset1_svr1_hp2_setup2_setup2 = A0_svr1_hp2_setup2_setup2.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr1_hp2_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)

        
        A_infoset1_svr2_hp1_setup1_setup1 = A0_svr2_hp1_setup1_setup1.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr2_hp1_setup1_setup2, values[1][0]) # Attacker attacks a honeypot
        singleton = [A0_svr2_hp1_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)


        A_infoset1_svr2_hp2_setup1_setup1 = A0_svr2_hp2_setup1_setup1.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr2_hp2_setup1_setup2, values[1][1]) # Attacker attacks a honeypot
        singleton = [A0_svr2_hp2_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)


        self.set_payoff(A0_svr2_hp1_setup2_setup1, values[1][2]) # Attacker attacks a honeypot
        A_infoset1_svr2_hp1_setup2_setup2 = A0_svr2_hp1_setup2_setup2.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr2_hp1_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)


        self.set_payoff(A0_svr2_hp2_setup2_setup1, values[1][3]) # Attacker attacks a honeypot
        A_infoset1_svr2_hp2_setup2_setup2 = A0_svr2_hp2_setup2_setup2.append_move(self.A, 4) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr2_hp2_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)


        print('g.is_perfect_recall at A_infoset0: {}'.format(self.g.is_perfect_recall))
        
        # =============================================================================
        # Attacker successfully targets server 1
        self.build_subtree(A_infoset1_svr1_hp1_setup1_setup1, values[2][0], values[6][0], values[4:]) #'_svr1_hp1_setup1_setup1_')
        self.build_subtree(A_infoset1_svr1_hp2_setup1_setup1, values[2][1], values[6][0], values[4:]) #'_svr1_hp2_setup1_setup1_')
        self.build_subtree(A_infoset1_svr1_hp1_setup2_setup2, values[2][2], values[6][0], values[4:]) #'_svr1_hp1_setup2_setup2_')
        self.build_subtree(A_infoset1_svr1_hp2_setup2_setup2, values[2][3], values[6][0], values[4:]) #'_svr1_hp2_setup2_setup2_')
        # Attacker successfully targets server 2
        self.build_subtree(A_infoset1_svr2_hp1_setup1_setup1, values[3][0], values[6][0], values[4:]) #'_svr2_hp1_setup1_setup1_')
        self.build_subtree(A_infoset1_svr2_hp2_setup1_setup1, values[3][1], values[6][0], values[4:]) #'_svr2_hp2_setup1_setup1_')
        self.build_subtree(A_infoset1_svr2_hp1_setup2_setup2, values[3][2], values[6][0], values[4:]) #'_svr2_hp1_setup2_setup2_')
        self.build_subtree(A_infoset1_svr2_hp2_setup2_setup2, values[3][3], values[6][0], values[4:]) #'_svr2_hp2_setup2_setup2_')

        # =============================================================================
    
        print('g.is_perfect_recall: {}'.format(self.g.is_perfect_recall))
        print('len(C_infosetinit.members): {}'.format(len(C_infosetinit.members)))
        print('len(D_infoset0_svr1.members): {}'.format(len(D_infoset0_svr1.members)))
        print('len(D_infoset0_svr2.members): {}'.format(len(D_infoset0_svr2.members)))
        print('len(A_infoset0.members): {}'.format(len(A_infoset0.members)))
        print('len(A_infoset1_svr1_hp1_setup1_setup1.members): {}'.format(len(A_infoset1_svr1_hp1_setup1_setup1.members)))
        print('len(A_infoset1_svr1_hp2_setup1_setup1.members): {}'.format(len(A_infoset1_svr1_hp2_setup1_setup1.members)))
        print('len(A_infoset1_svr1_hp1_setup2_setup2.members): {}'.format(len(A_infoset1_svr1_hp1_setup2_setup2.members)))
        print('len(A_infoset1_svr1_hp2_setup2_setup2.members): {}'.format(len(A_infoset1_svr1_hp2_setup2_setup2.members)))
        print('len(A_infoset1_svr2_hp1_setup1_setup1.members): {}'.format(len(A_infoset1_svr2_hp1_setup1_setup1.members)))
        print('len(A_infoset1_svr2_hp2_setup1_setup1.members): {}'.format(len(A_infoset1_svr2_hp2_setup1_setup1.members)))
        print('len(A_infoset1_svr2_hp1_setup2_setup2.members): {}'.format(len(A_infoset1_svr2_hp1_setup2_setup2.members)))
        print('len(A_infoset1_svr2_hp2_setup2_setup2.members): {}'.format(len(A_infoset1_svr2_hp2_setup2_setup2.members)))
        print('len(D_infoset1_svr1_hp1_setup1_setup1_sd.members): {}'.format(len(A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[0].infoset.members)))
        print('len(D_infoset1_svr1_hp1_setup1_setup1_nd_quit.members): {}'.format(len(A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[1].infoset.members)))
        print('len(D_infoset1_svr1_hp1_setup1_setup1_fd.members): {}'.format(len(A_infoset1_svr1_hp1_setup1_setup1.members[0].children[1].children[0].infoset.members)))
        
        """
        print(type(g.strategies)) # <type 'gambit.lib.libgambit.GameStrategies'>
        for strategy in g.strategies:
            print(type(strategy)) # <type 'gambit.lib.libgambit.Strategy'>
            break
        """
        
        print('g.is_const_sum: {}'.format(self.g.is_const_sum))
        print('g.min_payoff: {}'.format(self.g.min_payoff))
        print('g.max_payoff: {}'.format(self.g.max_payoff))
        print('len(g.actions): {}'.format(len(self.g.actions)))
        print('len(g.infosets): {}'.format(len(self.g.infosets)))
        print('len(g.strategies): {}'.format(len(self.g.strategies))) # 20
        print('len(g.contingencies): {}'.format(len(self.g.contingencies))) # 64
        print('g.is_perfect_recall: {}'.format(self.g.is_perfect_recall))
        print("________________________________")
        """
        print(type(g.contingencies)) # <class 'gambit.gameiter.Contingencies'>
        payoff = 0
        for profile in g.contingencies:
            print(type(profile)) # <type 'list'>
            print(len(profile)) # len = 2
            print(type(g[profile])) # <type 'gambit.lib.libgambit.TreeGameOutcome'>
            g[profile][0] = payoff
            payoff += 1
            g[profile][1] = payoff
            payoff += 1    
            print(g[profile][0])
            print(g[profile][1])
            break
        """
        
        self.write_file()
        print("write_file done")
        """
        -rwxrwxr-x 1 kfookwai kfookwai 10721197 Apr 19 11:55 gambit-simpdiv
        -rwxrwxr-x 1 kfookwai kfookwai 12745657 Apr 19 11:55 gambit-lp
        -rwxrwxr-x 1 kfookwai kfookwai 11326404 Apr 19 11:55 gambit-logit
        -rwxrwxr-x 1 kfookwai kfookwai 10999370 Apr 19 11:55 gambit-liap
        -rwxrwxr-x 1 kfookwai kfookwai 13355536 Apr 19 11:54 gambit-lcp
        -rwxrwxr-x 1 kfookwai kfookwai 11543635 Apr 19 11:54 gambit-ipa
        -rwxrwxr-x 1 kfookwai kfookwai 11629700 Apr 19 11:54 gambit-gnm
        -rwxrwxr-x 1 kfookwai kfookwai 10561803 Apr 19 11:54 gambit-enumpure
        -rwxrwxr-x 1 kfookwai kfookwai 17039555 Apr 19 11:54 gambit-enumpoly
        -rwxrwxr-x 1 kfookwai kfookwai 12777731 Apr 19 11:53 gambit-enummixed
        """
        pathlist = ['/data/shared/kfookwai/remote/wm_lua_study/oop_keras_py36/game_theory/gambit-15.1.1']
        os.environ["PATH"] += os.pathsep + os.pathsep.join(pathlist)
        
        solver = gambit.nash.ExternalLogitSolver()
        
        """
        http://www.gambit-project.org/gambit13/pyapi.html
        
        solver.solve(g)
        the returned profile is a gambit.BehavProfile
        
        
        solver.solve(g, use_strategic=True)
        it is a gambit.MixedProfile
        """
        self.result = solver.solve(self.g)
        
        print('len(result): {}'.format(len(self.result)))
        print(self.result)
        
        # bp is behaviour profile since we have an EXTENSIVE FORM GAME.
        bp = self.result[0]
        print("________________________________")
        # The Lyapunov value is a non-negative number which is zero exactly at Nash equilibria.
        print('Lyapunov value: {}'.format(bp.liap_value()))
        
        print('Prob of D_infoset0_svr1: {}'.format(bp[D_infoset0_svr1]))
        print('Prob of D_infoset0_svr2: {}'.format(bp[D_infoset0_svr2]))
        print('Prob of A_infoset0: {}'.format(bp[A_infoset0]))
        print('Prob of A_infoset1_svr1_hp1_setup1_setup1: {}'.format(bp[A_infoset1_svr1_hp1_setup1_setup1]))
        print('Prob of A_infoset1_svr1_hp2_setup1_setup1: {}'.format(bp[A_infoset1_svr1_hp2_setup1_setup1]))
        print('Prob of A_infoset1_svr1_hp1_setup2_setup2: {}'.format(bp[A_infoset1_svr1_hp1_setup2_setup2]))
        print('Prob of A_infoset1_svr1_hp2_setup2_setup2: {}'.format(bp[A_infoset1_svr1_hp2_setup2_setup2]))
        print('Prob of A_infoset1_svr2_hp1_setup1_setup1: {}'.format(bp[A_infoset1_svr2_hp1_setup1_setup1]))
        print('Prob of A_infoset1_svr2_hp2_setup1_setup1: {}'.format(bp[A_infoset1_svr2_hp2_setup1_setup1]))
        print('Prob of A_infoset1_svr2_hp1_setup2_setup2: {}'.format(bp[A_infoset1_svr2_hp1_setup2_setup2]))
        print('Prob of A_infoset1_svr2_hp2_setup2_setup2: {}'.format(bp[A_infoset1_svr2_hp2_setup2_setup2]))
        print("________________________________")
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_sd: {}'.format(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_nd: {}'.format(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_fd: {}'.format(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_p3_sd: {}'.format(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_sd: {}'.format(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_nd: {}'.format(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_fd: {}'.format(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_p3_sd: {}'.format(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_sd: {}'.format(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_nd: {}'.format(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_fd: {}'.format(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_p3_sd: {}'.format(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[2].children[0].children[0].infoset]))

        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_sd: {}'.format(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_nd: {}'.format(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_fd: {}'.format(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_p3_sd: {}'.format(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[2].children[0].children[0].infoset]))

        
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_sd: {}'.format(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_nd: {}'.format(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_fd: {}'.format(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_p3_sd: {}'.format(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[2].children[0].children[0].infoset]))

        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_sd: {}'.format(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_nd: {}'.format(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_fd: {}'.format(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_p3_sd: {}'.format(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_sd: {}'.format(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_nd: {}'.format(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_fd: {}'.format(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_p3_sd: {}'.format(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[2].children[0].children[0].infoset]))

        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_sd: {}'.format(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_nd: {}'.format(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_fd: {}'.format(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_p3_sd: {}'.format(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[2].children[0].children[0].infoset]))

        print(bp.payoff(self.A))
        print(bp.payoff(self.D))
        
        print('Number of attacker private chance nodes: ' + str(len(self.attacker_private_chance_nodes)))
        print('Number of defender private chance nodes: ' + str(len(self.defender_private_chance_nodes)))
        print('Number of public chance nodes: ' + str(len(self.public_chance_nodes)))
        #print('realiz_prob(A_infoset0): {}'.format(bp.realiz_prob(A_infoset0)))
        #print('realiz_prob(D_infoset0): {}'.format(bp.realiz_prob(D_infoset0)))
        
        print("______________________")
        print("Writing to csv")
        '''
        export_file = open(str(self.file_name) + "_gambit.csv", "wb")
        with export_file as csvfile:
            resultwriter = csv.writer(csvfile, delimiter = ' ',
                                      quotechar = '|', quoting=csv.QUOTE_MINIMAL)
            resultwriter.writerow(['Infoset'] + ['Probabilities'])
            resultwriter.writerow([''] + ['hp1_setup1'] + ['hp2_setup1'] + ['hp1_setup2'] + ['hp2_setup2'])
            resultwriter.writerow(['D_infoset0_svr1'] + [str(bp[D_infoset0_svr1][0])] + [str(bp[D_infoset0_svr1][1])] + [str(bp[D_infoset0_svr1][2])] + [str(bp[D_infoset0_svr1][3])])
            resultwriter.writerow(['D_infoset0_svr2'] + [str(bp[D_infoset0_svr2][0])] + [str(bp[D_infoset0_svr2][1])] + [str(bp[D_infoset0_svr2][2])] + [str(bp[D_infoset0_svr2][3])])
            resultwriter.writerow([])
            
            resultwriter.writerow([''] + ['setup1'] + ['setup2'])
            resultwriter.writerow(['A_infoset0'] + [str(bp[A_infoset0][0])] + [str(bp[A_infoset0][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow([''] + ['p1'] + ['p2'] + ['p3'] + ['quit'])
            resultwriter.writerow(['A_infoset1_svr1_hp1_setup1_setup1'] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1][0])] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1][1])] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1][2])] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1][3])])
            resultwriter.writerow(['A_infoset1_svr1_hp2_setup1_setup1'] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1][0])] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1][1])] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1][2])] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1][3])])
            resultwriter.writerow(['A_infoset1_svr1_hp1_setup2_setup2'] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2][0])] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2][1])] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2][2])] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2][3])])
            resultwriter.writerow(['A_infoset1_svr1_hp2_setup2_setup2'] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2][0])] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2][1])] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2][2])] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2][3])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['A_infoset1_svr2_hp1_setup1_setup1'] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1][0])] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1][1])] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1][2])] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1][3])])
            resultwriter.writerow(['A_infoset1_svr2_hp2_setup1_setup1'] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1][0])] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1][1])] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1][2])] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1][3])])
            resultwriter.writerow(['A_infoset1_svr2_hp1_setup2_setup2'] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2][0])] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2][1])] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2][2])] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2][3])])
            resultwriter.writerow(['A_infoset1_svr2_hp2_setup2_setup2'] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2][0])] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2][1])] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2][2])] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2][3])])
            resultwriter.writerow([])
            
            resultwriter.writerow([''] + ['b'] + ['nb'])
            resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_sd'] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_nd'] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_fd'] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr1_hp1_setup1_setup1.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_sd'] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_nd'] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_fd'] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr1_hp2_setup1_setup1.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2_sd'] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2_nd'] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2_fd'] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr1_hp1_setup2_setup2.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_sd'] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_nd'] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_fd'] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr1_hp2_setup2_setup2.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_sd'] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_nd'] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_fd'] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr2_hp1_setup1_setup1.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_sd'] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_nd'] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_fd'] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr2_hp2_setup1_setup1.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2_sd'] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2_nd'] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2_fd'] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr2_hp1_setup2_setup2.members[0].children[0].children[2].infoset][1])])
            resultwriter.writerow([])
            
            resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_sd'] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[0].infoset][0])] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[0].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_nd'] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[1].infoset][0])] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[1].infoset][1])])
            resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_fd'] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[2].infoset][0])] + [str(bp[A_infoset1_svr2_hp2_setup2_setup2.members[0].children[0].children[2].infoset][1])])
        
        print("Writing to csv done")    
        print("______________________")
        '''    
        print("Pickling")

        combined = [self.convert_list_of_nodes_to_list_of_tuples(self.attacker_private_chance_nodes),
                    self.convert_list_of_nodes_to_list_of_tuples(self.defender_private_chance_nodes),
                    self.convert_list_of_nodes_to_list_of_tuples(self.public_chance_nodes), 
                    self.convert_tnv_to_list_of_tuples(self.terminal_node_vectors)]
        with open(self.file_name + "_lists.txt", "wb") as f:            
            pickle.dump(combined, f)
            
        print("Pickling done")
        
        print('Done')
        
        #return the infosets because the ide can't handle constructing the entire tree at once
        return [bp, A_infoset1_svr1_hp1_setup1_setup1, A_infoset1_svr1_hp2_setup1_setup1,
                A_infoset1_svr1_hp1_setup2_setup2, A_infoset1_svr1_hp2_setup2_setup2,
                A_infoset1_svr2_hp1_setup1_setup1, A_infoset1_svr2_hp2_setup1_setup1,
                A_infoset1_svr2_hp1_setup2_setup2, A_infoset1_svr2_hp2_setup2_setup2]
     
        
    def save_results_to_csv(self, runs):
        print("Writing to csv")
        export_file = open(str(self.file_name) + '_' + str(runs) + "_runs_pcs.csv", "wb")
        with export_file as csvfile:
            resultwriter = csv.writer(csvfile, delimiter = ' ',
                                      quotechar = '|', quoting=csv.QUOTE_MINIMAL)
            resultwriter.writerow(['Infoset'] + ['Probabilities'])
            resultwriter.writerow([''] + ['hp1_setup1'] + ['hp2_setup1'] + ['hp1_setup2'] + ['hp2_setup2'])
            resultwriter.writerow(['D_infoset0_svr1'] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].infoset))[0])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].infoset))[1])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].infoset))[2])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].infoset))[3])])
            resultwriter.writerow(['D_infoset0_svr2'] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].infoset))[0])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].infoset))[1])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].infoset))[2])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].infoset))[3])])
            resultwriter.writerow([])
            
            resultwriter.writerow([''] + ['setup1'] + ['setup2'])
            resultwriter.writerow(['A_infoset0'] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].infoset))[0])] \
                                  + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].infoset))[1])])
            resultwriter.writerow([])
            
            if not self.g.root.children[0].children[0].children[0].is_terminal:
                resultwriter.writerow([''] + ['p1'] + ['p2'] + ['p3'] + ['quit'])
                resultwriter.writerow(['A_infoset1_svr1_hp1_setup1_setup1'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].infoset))[3])])
                resultwriter.writerow(['A_infoset1_svr1_hp2_setup1_setup1'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].infoset))[3])])
                resultwriter.writerow(['A_infoset1_svr1_hp1_setup2_setup2'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].infoset))[3])])
                resultwriter.writerow(['A_infoset1_svr1_hp2_setup2_setup2'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].infoset))[3])])
                resultwriter.writerow([])
                
                resultwriter.writerow(['A_infoset1_svr2_hp1_setup1_setup1'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].infoset))[3])])
                resultwriter.writerow(['A_infoset1_svr2_hp2_setup1_setup1'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].infoset))[3])])
                resultwriter.writerow(['A_infoset1_svr2_hp1_setup2_setup2'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].infoset))[3])])
                resultwriter.writerow(['A_infoset1_svr2_hp2_setup2_setup2'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].infoset))[3])])
                resultwriter.writerow([])
                
                
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup1_setup1_dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[0].children[0].children[2].children[0].children[0].infoset))[1])])
                
                resultwriter.writerow([])
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup1_setup1_dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[1].children[0].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp1_setup2_setup2__dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[2].children[1].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr1_hp2_setup2_setup2_dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[0].children[3].children[1].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
                
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup1_setup1_dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[0].children[0].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup1_setup1_dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[1].children[0].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp1_setup2_setup2__dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[2].children[1].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
                
                resultwriter.writerow([''] + ['b'] + ['nb'])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[0].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[0].children[0].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_nd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[0].children[0].children[1].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[0].children[0].children[1].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_fd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[0].children[1].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[0].children[1].children[0].infoset))[1])])
                resultwriter.writerow(['D_infoset1_svr2_hp2_setup2_setup2_dos_sd'] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[2].children[0].children[0].infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(self.g.root.children[1].children[3].children[1].children[2].children[0].children[0].infoset))[1])])
                resultwriter.writerow([])
            
                if not self.g.root.children[0].children[0].children[0].children[0].children[0].children[0].children[1].is_terminal:
                    def subtree_root(name, number, root_node):
                        resultwriter.writerow([''] + ['p1'] + ['p2'] + ['p3'] + ['quit'])
                        resultwriter.writerow(['A_infoset' + str(number) + name] \
                                      + [str(self.get_average_strat(self.strategy_table, str(root_node.infoset))[0])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(root_node.infoset))[1])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(root_node.infoset))[2])] \
                                      + [str(self.get_average_strat(self.strategy_table, str(root_node.infoset))[3])])
                        resultwriter.writerow([''] + ['b'] + ['nb'])
                        resultwriter.writerow(['D_infoset' + str(number) + name + '_sd'] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[0].children[0].children[0].infoset))[0])] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[0].children[0].children[0].infoset))[1])])
                        resultwriter.writerow(['D_infoset' + str(number) + name + '_nd'] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[0].children[0].children[1].infoset))[0])] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[0].children[0].children[1].infoset))[1])])
                        resultwriter.writerow(['D_infoset' + str(number) + name + '_fd'] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[0].children[1].children[0].infoset))[0])] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[0].children[1].children[0].infoset))[1])])
                        resultwriter.writerow(['D_infoset' + str(number) + name + '_dos_sd'] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[2].children[0].children[0].infoset))[0])] \
                                              + [str(self.get_average_strat(self.strategy_table, str(root_node.children[2].children[0].children[0].infoset))[1])])
                        resultwriter.writerow([])
                        print("Subtree row done")
                    
                    subtree_root('svr1_hp1_setup1_setup1_p1_sd_nb', 2, self.g.root.children[0].children[0].children[0].children[0].children[0].children[0].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p1_nd_nb', 2, self.g.root.children[0].children[0].children[0].children[0].children[0].children[1].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p1_fd_nb', 2, self.g.root.children[0].children[0].children[0].children[0].children[1].children[0].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p1_fnd_nb', 2, self.g.root.children[0].children[0].children[0].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp1_setup1_setup1_p2_sd_nb', 2, self.g.root.children[0].children[0].children[0].children[1].children[0].children[0].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p2_nd_nb', 2, self.g.root.children[0].children[0].children[0].children[1].children[0].children[1].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p2_fd_nb', 2, self.g.root.children[0].children[0].children[0].children[1].children[1].children[0].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p2_fnd_nb', 2, self.g.root.children[0].children[0].children[0].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp1_setup1_setup1_p3_dos_sd_nb', 2, self.g.root.children[0].children[0].children[0].children[2].children[0].children[0].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p3_nd_nb', 2, self.g.root.children[0].children[0].children[0].children[2].children[0].children[1].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p3_fd_nb', 2, self.g.root.children[0].children[0].children[0].children[2].children[1].children[0].children[1])
                    subtree_root('svr1_hp1_setup1_setup1_p3_fnd_nb', 2, self.g.root.children[0].children[0].children[0].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
                    subtree_root('svr1_hp2_setup1_setup1_p1_sd_nb', 2, self.g.root.children[0].children[1].children[0].children[0].children[0].children[0].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p1_nd_nb', 2, self.g.root.children[0].children[1].children[0].children[0].children[0].children[1].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p1_fd_nb', 2, self.g.root.children[0].children[1].children[0].children[0].children[1].children[0].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p1_fnd_nb', 2, self.g.root.children[0].children[1].children[0].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp2_setup1_setup1_p2_sd_nb', 2, self.g.root.children[0].children[1].children[0].children[1].children[0].children[0].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p2_nd_nb', 2, self.g.root.children[0].children[1].children[0].children[1].children[0].children[1].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p2_fd_nb', 2, self.g.root.children[0].children[1].children[0].children[1].children[1].children[0].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p2_fnd_nb', 2, self.g.root.children[0].children[1].children[0].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp2_setup1_setup1_p3_dos_sd_nb', 2, self.g.root.children[0].children[1].children[0].children[2].children[0].children[0].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p3_nd_nb', 2, self.g.root.children[0].children[1].children[0].children[2].children[0].children[1].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p3_fd_nb', 2, self.g.root.children[0].children[1].children[0].children[2].children[1].children[0].children[1])
                    subtree_root('svr1_hp2_setup1_setup1_p3_fnd_nb', 2, self.g.root.children[0].children[1].children[0].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
                    subtree_root('svr1_hp1_setup2_setup2_p1_sd_nb', 2, self.g.root.children[0].children[2].children[1].children[0].children[0].children[0].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p1_nd_nb', 2, self.g.root.children[0].children[2].children[1].children[0].children[0].children[1].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p1_fd_nb', 2, self.g.root.children[0].children[2].children[1].children[0].children[1].children[0].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p1_fnd_nb', 2, self.g.root.children[0].children[2].children[1].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp1_setup2_setup2_p2_sd_nb', 2, self.g.root.children[0].children[2].children[1].children[1].children[0].children[0].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p2_nd_nb', 2, self.g.root.children[0].children[2].children[1].children[1].children[0].children[1].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p2_fd_nb', 2, self.g.root.children[0].children[2].children[1].children[1].children[1].children[0].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p2_fnd_nb', 2, self.g.root.children[0].children[2].children[1].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp1_setup2_setup2_p3_dos_sd_nb', 2, self.g.root.children[0].children[2].children[1].children[2].children[0].children[0].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p3_nd_nb', 2, self.g.root.children[0].children[2].children[1].children[2].children[0].children[1].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p3_fd_nb', 2, self.g.root.children[0].children[2].children[1].children[2].children[1].children[0].children[1])
                    subtree_root('svr1_hp1_setup2_setup2_p3_fnd_nb', 2, self.g.root.children[0].children[2].children[1].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
                    subtree_root('svr1_hp2_setup2_setup2_p1_sd_nb', 2, self.g.root.children[0].children[3].children[1].children[0].children[0].children[0].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p1_nd_nb', 2, self.g.root.children[0].children[3].children[1].children[0].children[0].children[1].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p1_fd_nb', 2, self.g.root.children[0].children[3].children[1].children[0].children[1].children[0].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p1_fnd_nb', 2, self.g.root.children[0].children[3].children[1].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp2_setup2_setup2_p2_sd_nb', 2, self.g.root.children[0].children[3].children[1].children[1].children[0].children[0].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p2_nd_nb', 2, self.g.root.children[0].children[3].children[1].children[1].children[0].children[1].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p2_fd_nb', 2, self.g.root.children[0].children[3].children[1].children[1].children[1].children[0].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p2_fnd_nb', 2, self.g.root.children[0].children[3].children[1].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr1_hp2_setup2_setup2_p3_dos_sd_nb', 2, self.g.root.children[0].children[3].children[1].children[2].children[0].children[0].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p3_nd_nb', 2, self.g.root.children[0].children[3].children[1].children[2].children[0].children[1].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p3_fd_nb', 2, self.g.root.children[0].children[3].children[1].children[2].children[1].children[0].children[1])
                    subtree_root('svr1_hp2_setup2_setup2_p3_fnd_nb', 2, self.g.root.children[0].children[3].children[1].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
    
                    subtree_root('svr2_hp1_setup1_setup1_p1_sd_nb', 2, self.g.root.children[1].children[0].children[0].children[0].children[0].children[0].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p1_nd_nb', 2, self.g.root.children[1].children[0].children[0].children[0].children[0].children[1].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p1_fd_nb', 2, self.g.root.children[1].children[0].children[0].children[0].children[1].children[0].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p1_fnd_nb', 2, self.g.root.children[1].children[0].children[0].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp1_setup1_setup1_p2_sd_nb', 2, self.g.root.children[1].children[0].children[0].children[1].children[0].children[0].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p2_nd_nb', 2, self.g.root.children[1].children[0].children[0].children[1].children[0].children[1].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p2_fd_nb', 2, self.g.root.children[1].children[0].children[0].children[1].children[1].children[0].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p2_fnd_nb', 2, self.g.root.children[1].children[0].children[0].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp1_setup1_setup1_p3_dos_sd_nb', 2, self.g.root.children[1].children[0].children[0].children[2].children[0].children[0].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p3_nd_nb', 2, self.g.root.children[1].children[0].children[0].children[2].children[0].children[1].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p3_fd_nb', 2, self.g.root.children[1].children[0].children[0].children[2].children[1].children[0].children[1])
                    subtree_root('svr2_hp1_setup1_setup1_p3_fnd_nb', 2, self.g.root.children[1].children[0].children[0].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
                    subtree_root('svr2_hp2_setup1_setup1_p1_sd_nb', 2, self.g.root.children[1].children[1].children[0].children[0].children[0].children[0].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p1_nd_nb', 2, self.g.root.children[1].children[1].children[0].children[0].children[0].children[1].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p1_fd_nb', 2, self.g.root.children[1].children[1].children[0].children[0].children[1].children[0].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p1_fnd_nb', 2, self.g.root.children[1].children[1].children[0].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp2_setup1_setup1_p2_sd_nb', 2, self.g.root.children[1].children[1].children[0].children[1].children[0].children[0].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p2_nd_nb', 2, self.g.root.children[1].children[1].children[0].children[1].children[0].children[1].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p2_fd_nb', 2, self.g.root.children[1].children[1].children[0].children[1].children[1].children[0].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p2_fnd_nb', 2, self.g.root.children[1].children[1].children[0].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp2_setup1_setup1_p3_dos_sd_nb', 2, self.g.root.children[1].children[1].children[0].children[2].children[0].children[0].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p3_nd_nb', 2, self.g.root.children[1].children[1].children[0].children[2].children[0].children[1].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p3_fd_nb', 2, self.g.root.children[1].children[1].children[0].children[2].children[1].children[0].children[1])
                    subtree_root('svr2_hp2_setup1_setup1_p3_fnd_nb', 2, self.g.root.children[1].children[1].children[0].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
                    subtree_root('svr2_hp1_setup2_setup2_p1_sd_nb', 2, self.g.root.children[1].children[2].children[1].children[0].children[0].children[0].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p1_nd_nb', 2, self.g.root.children[1].children[2].children[1].children[0].children[0].children[1].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p1_fd_nb', 2, self.g.root.children[1].children[2].children[1].children[0].children[1].children[0].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p1_fnd_nb', 2, self.g.root.children[1].children[2].children[1].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp1_setup2_setup2_p2_sd_nb', 2, self.g.root.children[1].children[2].children[1].children[1].children[0].children[0].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p2_nd_nb', 2, self.g.root.children[1].children[2].children[1].children[1].children[0].children[1].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p2_fd_nb', 2, self.g.root.children[1].children[2].children[1].children[1].children[1].children[0].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p2_fnd_nb', 2, self.g.root.children[1].children[2].children[1].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp1_setup2_setup2_p3_dos_sd_nb', 2, self.g.root.children[1].children[2].children[1].children[2].children[0].children[0].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p3_nd_nb', 2, self.g.root.children[1].children[2].children[1].children[2].children[0].children[1].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p3_fd_nb', 2, self.g.root.children[1].children[2].children[1].children[2].children[1].children[0].children[1])
                    subtree_root('svr2_hp1_setup2_setup2_p3_fnd_nb', 2, self.g.root.children[1].children[2].children[1].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    
                    subtree_root('svr2_hp2_setup2_setup2_p1_sd_nb', 2, self.g.root.children[1].children[3].children[1].children[0].children[0].children[0].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p1_nd_nb', 2, self.g.root.children[1].children[3].children[1].children[0].children[0].children[1].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p1_fd_nb', 2, self.g.root.children[1].children[3].children[1].children[0].children[1].children[0].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p1_fnd_nb', 2, self.g.root.children[1].children[3].children[1].children[0].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp2_setup2_setup2_p2_sd_nb', 2, self.g.root.children[1].children[3].children[1].children[1].children[0].children[0].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p2_nd_nb', 2, self.g.root.children[1].children[3].children[1].children[1].children[0].children[1].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p2_fd_nb', 2, self.g.root.children[1].children[3].children[1].children[1].children[1].children[0].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p2_fnd_nb', 2, self.g.root.children[1].children[3].children[1].children[1].children[1].children[1].children[1])
                    resultwriter.writerow([])
                    subtree_root('svr2_hp2_setup2_setup2_p3_dos_sd_nb', 2, self.g.root.children[1].children[3].children[1].children[2].children[0].children[0].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p3_nd_nb', 2, self.g.root.children[1].children[3].children[1].children[2].children[0].children[1].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p3_fd_nb', 2, self.g.root.children[1].children[3].children[1].children[2].children[1].children[0].children[1])
                    subtree_root('svr2_hp2_setup2_setup2_p3_fnd_nb', 2, self.g.root.children[1].children[3].children[1].children[2].children[1].children[1].children[1])
                    resultwriter.writerow([])
            print("Writing to csv done")   
            
    def get_game_tree(self):
        return self.g
    
    def delete_game_tree(self):
        self.g.root.delete_tree()
        self.attacker_private_chance_nodes = []
        self.defender_private_chance_nodes = []
        self.public_chance_nodes = []
        self.terminal_node_vectors = []
        self.terminal_nodes = []
        
        print("Tree deleted")
        print("Children of root of tree" + str(self.g.root.children))
        
    def init_regret_strategy_mem_tables(self):
        self.regret_table = {}
        self.strategy_table = {}
        self.m = [{}, {}]
        self.init_regret_strategy_table()
        self.init_mem_table()
        
    def get_result(self):
        if not hasattr(self, 'result'):
            self.generate_game()
        return self.result
    
    def run_sim(self, count, *bp):
        if list(bp) == []:
            if not hasattr(self, 'result'):
                bp = self.generate_game()
            else:
                bp = self.result[0]
        else:
            bp = list(bp)[0]
        att_score = 0.0
        runs = 0
        start = time.time()
        depth = 0
        choices = []
        while runs < count:
            current_node = self.g.root
            cumulative_prob = fraction(0, 1)
            while not current_node.is_terminal:
                rn = random.random()
                depth += 1
                for action in range(len(current_node.infoset.actions)):
                    if (current_node.infoset.player == self.C):
                        cumulative_prob += current_node.infoset.actions[action].prob
                    else:
                        cumulative_prob += bp[current_node.infoset][action]
                    if rn < cumulative_prob:
                        if not (depth == 7 and action == 1):
                            current_node = current_node.children[action]
                            choices.append(action)
                        cumulative_prob = fraction(0, 1)
                        break
            if depth == 7 and action == 1 and self.subtrees != []:
                att_score += self.subtrees[choices[0] * 48 + choices[1] * 12 + choices[3] * 4 + choices[4] * 1].run_sim(1)
            else:
                att_score += current_node.outcome[0] 
            del choices [:] 

            runs += 1
            depth = 0
            
            if runs % 10000 == 0:
                print(runs)
        end = time.time()
        print("Time taken: " + str(end - start) + " seconds")
        return att_score / runs
    
    def run_industry_sim(self, count, prob):
        if not hasattr(self, 'result'):
            self.generate_game()
        industry_bp = BPEdited(self.result[0], self.g)
        for d in self.g.root.children:
            for a in d.children:
                for a2 in a.children:
                    if not a2.is_terminal:
                        industry_bp.set_D_infoset_subtree_fd([prob, 1-prob], a2)
                        industry_bp.set_D_infoset_subtree_sd([prob, 1-prob], a2)
        modified_bp = []
        solver = gambit.nash.ExternalLogitSolver()
        for i in range(len(self.subtrees)):
            if not hasattr(self.subtrees[i], 'result'):
                self.subtrees[i].result = solver.solve(self.subtrees[i].g)
            industry_subtree_bp = BPEdited(self.subtrees[i].result[0], self.subtrees[i].get_game_tree())
            industry_subtree_bp.set_D_infoset_subtree_fd([prob, 1-prob], self.subtrees[i].get_game_tree().root)
            industry_subtree_bp.set_D_infoset_subtree_sd([prob, 1-prob], self.subtrees[i].get_game_tree().root)
            modified_bp.append(industry_bp.get_bp())
        bp = industry_bp.get_bp()
        att_score = 0.0
        runs = 0
        start = time.time()
        depth = 0
        choices = []
        while runs < count:
            current_node = self.g.root
            cumulative_prob = fraction(0, 1)
            while not current_node.is_terminal:
                rn = random.random()
                depth += 1
                for action in range(len(current_node.infoset.actions)):
                    if (current_node.infoset.player == self.C):
                        cumulative_prob += current_node.infoset.actions[action].prob
                    else:
                        cumulative_prob += bp[current_node.infoset][action]
                    if rn < cumulative_prob:
                        if not (depth == 6 and action == 1):
                            current_node = current_node.children[action]
                            choices.append(action)
                        cumulative_prob = fraction(0, 1)
                        break
            if depth == 6 and action == 1:
                att_score += modified_bp[choices[0] * 48 + choices[1] * 12 + choices[3] * 4 + choices[4] * 1].run_sim(1)
            else:
                att_score += current_node.outcome[0] 
            del choices [:] 
            runs += 1
            depth = 0

            if runs % 10000 == 0:
                print(runs)
        end = time.time()
        print("Time taken: " + str(end - start) + " seconds")
        return att_score / runs
    
    def run_sim_PCS(self, count):
        att_score = 0.0
        runs = 0
        start = time.time()

        while runs < count:
            current_node = self.g.root
            cumulative_prob = fraction(0, 1)
            while not current_node.is_terminal:
                rn = random.random()

                for action_idx in range(len(current_node.infoset.actions)):
                    if (current_node.infoset.player == self.C):
                        assert(0 <= current_node.infoset.actions[action_idx].prob)
                        assert(current_node.infoset.actions[action_idx].prob <= 1)
                        cumulative_prob += current_node.infoset.actions[action_idx].prob
                        assert(0 <= cumulative_prob and cumulative_prob <= 1)
                    else:
                        assert(0 <= self.get_average_strat(self.strategy_table, str(current_node.infoset))[action_idx])
                        assert(self.get_average_strat(self.strategy_table, str(current_node.infoset))[action_idx] <= 1)
                        cumulative_prob += self.get_average_strat(self.strategy_table, str(current_node.infoset))[action_idx]
                        assert(0 <= cumulative_prob and cumulative_prob <= 1)
                    if rn < cumulative_prob:
                        current_node = current_node.children[action_idx]
                        cumulative_prob = fraction(0, 1)
                        break
            att_score += current_node.outcome[0]
            runs += 1            
            if runs % 10000 == 0:
                print(runs)
                print(att_score)
        end = time.time()
        print("Time taken: " + str(end - start) + " seconds")
        return att_score / runs
    
    def run_industry_sim_PCS(self, count, prob):
        industry_strat = {}
        for infoset in self.g.infosets:
            values = []
            # Modify defender's blocking probability
            if infoset.player == self.D and len(infoset.actions) == 2:
                values.append(prob)
                values.append(1 - prob)
            else:
                # Copy the values from the original strategy table
                for i in range(len(infoset.actions)):
                    values.append(self.strategy_table[str(infoset)][i])
            industry_strat[str(infoset)] = values[:]
        att_score = 0.0
        runs = 0
        start = time.time()
        while runs < count:
            current_node = self.g.root
            cumulative_prob = fraction(0, 1)
            while not current_node.is_terminal:
                rn = random.random()
                for action_idx in range(len(current_node.infoset.actions)):
                    if (current_node.infoset.player == self.C):
                        assert(0 <= current_node.infoset.actions[action_idx].prob)
                        assert(current_node.infoset.actions[action_idx].prob <= 1)
                        cumulative_prob += current_node.infoset.actions[action_idx].prob
                        assert(0 <= cumulative_prob and cumulative_prob <= 1)
                    else:
                        assert(0 <= self.get_average_strat(self.strategy_table, str(current_node.infoset))[action_idx])
                        assert(self.get_average_strat(self.strategy_table, str(current_node.infoset))[action_idx] <= 1)
                        cumulative_prob += self.get_average_strat(industry_strat, str(current_node.infoset))[action_idx]
                        assert(0 <= cumulative_prob and cumulative_prob <= 1)
                    if rn < cumulative_prob:
                        current_node = current_node.children[action_idx]
                        cumulative_prob = fraction(0, 1)
                        break
            att_score +=  current_node.outcome[0]
            runs += 1
            if runs % 10000 == 0:
                print(runs)
        end = time.time()
        print("Time taken: " + str(end - start) + " seconds")
        return att_score / runs
    
    def generate_game2(self, infosets, v):
        values = v[:]
        for i in range(1,9):
            for c1 in infosets[i].members[0].children: #chance node 1
                if c1.player == self.C:
                    for c2 in c1.children:    #Chance node 2
                        for d in c2.children: #Defender node
                            payoff = d.children[1].outcome.__getitem__(self.A)
                            d.children[1].outcome.delete()
                            for tnv in self.terminal_node_vectors:
                                if d.children[1] in tnv:
                                    tnv.remove(d.children[1])
                                    if len(tnv) == 0:
                                        self.terminal_node_vectors.remove(tnv)
                                    break
                            if d.children[1] in self.terminal_nodes:
                                self.terminal_nodes.remove(d.children[1])
                            next_level = d.children[1].append_move(self.A, 4)
                            self.build_subtree(next_level, payoff, values[6][1], values[4:])
        self.write_file()
        print("write_file done")
        
    def generate_game_solved_subtree(self, infosets, v):
        values = v[:]
        del self.subtrees[:] #Delete existing subtrees if any
        solver = gambit.nash.ExternalLogitSolver()
        for i in range(1,9):
            for c1 in infosets[i].members[0].children: #chance node 1
                if c1.player == self.C:
    
                    for c2 in c1.children:    #Chance node 2
                        for d in c2.children: #Defender node
                            payoff = d.children[1].outcome.__getitem__(self.A)
                            d.children[1].outcome.delete()
                            for tnv in self.terminal_node_vectors:
                                if d.children[1] in tnv:
                                    tnv.remove(d.children[1])
                                    if len(tnv) == 0:
                                        self.terminal_node_vectors.remove(tnv)
                                    break
                            if d.children[1] in self.terminal_nodes:
                                self.terminal_nodes.remove(d.children[1])
                            subtree = GameTree("subtree")
                            subtree_root_node = subtree.g.root
                            subtree_root_node.append_move(subtree.A, 4)
                            subtree.build_subtree(subtree_root_node.infoset, payoff, values[6][1], values[4:]) #get this from the payoff of the main tree
                            subtree_result = solver.solve(subtree.g)
                            self.set_payoff(d.children[1], int(subtree_result[0].payoff(subtree.A))) #set this as the payoff in the main 
                            self.subtrees.append(subtree) #Add the subtree into the list for future use
        print("________________________________")
        self.write_file()
        print("write_file done")
        print("________________________________")
        print('g.is_perfect_recall: {}'.format(self.g.is_perfect_recall))
        print('len(C_infosetinit.members): {}'.format(len(self.g.root.infoset.members)))
        print('len(D_infoset0_svr1.members): {}'.format(len(self.g.root.children[0].infoset.members)))
        print('len(D_infoset0_svr2.members): {}'.format(len(self.g.root.children[1].infoset.members)))
        print('len(A_infoset0.members): {}'.format(len(self.g.root.children[0].children[0].infoset.members)))
        print('len(A_infoset1_svr1_hp1_setup1_setup1.members): {}'.format(len(self.g.root.children[0].children[0].children[0].infoset.members)))
        print('len(A_infoset1_svr1_hp2_setup1_setup1.members): {}'.format(len(self.g.root.children[0].children[1].children[0].infoset.members)))
        print('len(A_infoset1_svr1_hp1_setup2_setup2.members): {}'.format(len(self.g.root.children[0].children[2].children[1].infoset.members)))
        print('len(A_infoset1_svr1_hp2_setup2_setup2.members): {}'.format(len(self.g.root.children[0].children[3].children[1].infoset.members)))
        print('len(A_infoset1_svr2_hp1_setup1_setup1.members): {}'.format(len(self.g.root.children[1].children[0].children[0].infoset.members)))
        print('len(A_infoset1_svr2_hp2_setup1_setup1.members): {}'.format(len(self.g.root.children[1].children[1].children[0].infoset.members)))
        print('len(A_infoset1_svr2_hp1_setup2_setup2.members): {}'.format(len(self.g.root.children[1].children[2].children[1].infoset.members)))
        print('len(A_infoset1_svr2_hp2_setup2_setup2.members): {}'.format(len(self.g.root.children[1].children[3].children[1].infoset.members)))
        print('len(D_infoset1_svr1_hp1_setup1_setup1_sd.members): {}'.format(len(self.g.root.children[0].children[0].children[0].children[0].children[0].children[0].infoset.members)))
        print('len(D_infoset1_svr1_hp1_setup1_setup1_nd.members): {}'.format(len(self.g.root.children[0].children[0].children[0].children[0].children[0].children[1].infoset.members)))
        print('len(D_infoset1_svr1_hp1_setup1_setup1_fd.members): {}'.format(len(self.g.root.children[0].children[0].children[0].children[0].children[1].children[0].infoset.members)))
        
        """
        print(type(g.strategies)) # <type 'gambit.lib.libgambit.GameStrategies'>
        for strategy in g.strategies:
            print(type(strategy)) # <type 'gambit.lib.libgambit.Strategy'>
            break
        """
        
        print('g.is_const_sum: {}'.format(self.g.is_const_sum))
        print('g.min_payoff: {}'.format(self.g.min_payoff))
        print('g.max_payoff: {}'.format(self.g.max_payoff))
        print('len(g.actions): {}'.format(len(self.g.actions)))
        print('len(g.infosets): {}'.format(len(self.g.infosets)))
        print('len(g.strategies): {}'.format(len(self.g.strategies))) # 20
        print('len(g.contingencies): {}'.format(len(self.g.contingencies))) # 64
        print('g.is_perfect_recall: {}'.format(self.g.is_perfect_recall))
        print("________________________________")

        self.result = solver.solve(self.g)
        
        print('len(result): {}'.format(len(self.result)))
        print(self.result)
        
        # bp is behaviour profile since we have an EXTENSIVE FORM GAME.
        bp = self.result[0]
        print("________________________________")
        # The Lyapunov value is a non-negative number which is zero exactly at Nash equilibria.
        print('Lyapunov value: {}'.format(bp.liap_value()))
        
        print('Prob of D_infoset0_svr1: {}'.format(bp[self.g.root.children[0].infoset]))
        print('Prob of D_infoset0_svr2: {}'.format(bp[self.g.root.children[1].infoset]))
        print('Prob of A_infoset0: {}'.format(bp[self.g.root.children[0].children[0].infoset]))
        print('Prob of A_infoset1_svr1_hp1_setup1_setup1: {}'.format(bp[self.g.root.children[0].children[0].children[0].infoset]))
        print('Prob of A_infoset1_svr1_hp2_setup1_setup1: {}'.format(bp[self.g.root.children[0].children[1].children[0].infoset]))
        print('Prob of A_infoset1_svr1_hp1_setup2_setup2: {}'.format(bp[self.g.root.children[0].children[2].children[1].infoset]))
        print('Prob of A_infoset1_svr1_hp2_setup2_setup2: {}'.format(bp[self.g.root.children[0].children[3].children[1].infoset]))
        print('Prob of A_infoset1_svr2_hp1_setup1_setup1: {}'.format(bp[self.g.root.children[1].children[0].children[0].infoset]))
        print('Prob of A_infoset1_svr2_hp2_setup1_setup1: {}'.format(bp[self.g.root.children[1].children[1].children[0].infoset]))
        print('Prob of A_infoset1_svr2_hp1_setup2_setup2: {}'.format(bp[self.g.root.children[1].children[2].children[1].infoset]))
        print('Prob of A_infoset1_svr2_hp2_setup2_setup2: {}'.format(bp[self.g.root.children[1].children[3].children[1].infoset]))
        print("________________________________")
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_sd: {}'.format(bp[self.g.root.children[0].children[0].children[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_nd: {}'.format(bp[self.g.root.children[0].children[0].children[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_fd: {}'.format(bp[self.g.root.children[0].children[0].children[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_p3_sd: {}'.format(bp[self.g.root.children[0].children[0].children[0].children[2].children[0].children[0].infoset]))
                
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_sd: {}'.format(bp[self.g.root.children[0].children[1].children[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_nd: {}'.format(bp[self.g.root.children[0].children[1].children[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup1_setup1_fd: {}'.format(bp[self.g.root.children[0].children[1].children[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup1_setup1_p3_sd: {}'.format(bp[self.g.root.children[0].children[1].children[0].children[2].children[0].children[0].infoset]))
            
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_sd: {}'.format(bp[self.g.root.children[0].children[2].children[1].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_nd: {}'.format(bp[self.g.root.children[0].children[2].children[1].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup2_setup2_fd: {}'.format(bp[self.g.root.children[0].children[2].children[1].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp1_setup2_setup1_p3_sd: {}'.format(bp[self.g.root.children[0].children[2].children[1].children[2].children[0].children[0].infoset]))

        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_sd: {}'.format(bp[self.g.root.children[0].children[3].children[1].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_nd: {}'.format(bp[self.g.root.children[0].children[3].children[1].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup2_setup2_fd: {}'.format(bp[self.g.root.children[0].children[3].children[1].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr1_hp2_setup2_setup1_p3_sd: {}'.format(bp[self.g.root.children[0].children[3].children[1].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_sd: {}'.format(bp[self.g.root.children[1].children[0].children[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_nd: {}'.format(bp[self.g.root.children[1].children[0].children[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_fd: {}'.format(bp[self.g.root.children[1].children[0].children[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup1_setup1_p3_sd: {}'.format(bp[self.g.root.children[1].children[0].children[0].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_sd: {}'.format(bp[self.g.root.children[1].children[1].children[0].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_nd: {}'.format(bp[self.g.root.children[1].children[1].children[0].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_fd: {}'.format(bp[self.g.root.children[1].children[1].children[0].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup1_setup1_p3_sd: {}'.format(bp[self.g.root.children[1].children[1].children[0].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_sd: {}'.format(bp[self.g.root.children[1].children[2].children[1].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_nd: {}'.format(bp[self.g.root.children[1].children[2].children[1].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_fd: {}'.format(bp[self.g.root.children[1].children[2].children[1].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp1_setup2_setup2_p3_sd: {}'.format(bp[self.g.root.children[1].children[2].children[1].children[2].children[0].children[0].infoset]))
        
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_sd: {}'.format(bp[self.g.root.children[1].children[3].children[1].children[0].children[0].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_nd: {}'.format(bp[self.g.root.children[1].children[3].children[1].children[0].children[0].children[1].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_fd: {}'.format(bp[self.g.root.children[1].children[3].children[1].children[0].children[1].children[0].infoset]))
        print('Prob of D_infoset1_svr2_hp2_setup2_setup2_p3_sd: {}'.format(bp[self.g.root.children[1].children[3].children[1].children[2].children[0].children[0].infoset]))

        for i in range(1): #len(self.subtrees)): #Print statements too long
            if not hasattr(self.subtrees[i], 'result'):
                self.subtrees[i].result = solver.solve(self.subtrees[i].g)
                print('Prob of A_infoset2 subtree ' + str(i) + ': {}'.format(self.subtrees[i].result[0][self.subtrees[i].get_game_tree().root.infoset]))
                print('Prob of D_infoset2_sd subtree ' + str(i) + ': {}'.format(self.subtrees[i].result[0][self.subtrees[i].get_game_tree().root.children[0].children[0].children[0].infoset]))
                print('Prob of D_infoset2_nd subtree ' + str(i) + ': {}'.format(self.subtrees[i].result[0][self.subtrees[i].get_game_tree().root.children[0].children[0].children[1].infoset]))
                print('Prob of D_infoset2_fd subtree ' + str(i) + ': {}'.format(self.subtrees[i].result[0][self.subtrees[i].get_game_tree().root.children[0].children[1].children[0].infoset]))
                print('Prob of D_infoset2_fd subtree ' + str(i) + ': {}'.format(self.subtrees[i].result[0][self.subtrees[i].get_game_tree().root.children[2].children[0].children[0].infoset]))
        print("Number of subtrees: " + str(len(self.subtrees)))
        print(bp.payoff(self.A))
        print(bp.payoff(self.D))
        
    def init_regret_strategy_table(self):
        for infoset in self.g.infosets:
            values = []
            for i in range(len(infoset.actions)):
                values.append(0)
            self.regret_table[str(infoset)] = values[:]
            self.strategy_table[str(infoset)] = values[:]
        print("Regret and strategy tables initialised")
        
    def init_mem_table(self):
        for player_id, player in enumerate(self.g.players):
            for infoset in self.g.infosets:
                ifs = []
                for member in infoset.members:                    
                    values = []
                    for i in range(len(infoset.actions)):
                        values.append(0)
                    ifs.append(values)
                self.m[player_id][str(infoset)] = ifs
        print("Memory table initialised")
        
    def init_u(self):
        u = [{}, {}]
        for player_id, player in enumerate(self.g.players):
            #For each infoset
            for infoset in self.g.infosets:
                if infoset.player == player: # If the infoset's player matches the current player
                    members = []
                    for m in infoset.members:
                        members.append(0)
                    u[player_id][str(infoset)] = members
        return u
                
    def init_pi_i(self, player):
        pi_i = {}
        for infoset in self.g.infosets:
            if infoset.player == player:
                values = []
                for i in range(len(infoset.members)):
                    memb = []
                    for a in range(len(infoset.actions)):
                        memb.append(1)
                    values.append(memb)    
                pi_i[str(infoset)] = values
        for node in self.terminal_nodes:
            pi_i[str(node)] = [[1]]
        return pi_i
    
    def walkTree(self, h, i, pi_i, pi_not_i):
        last_node_h = self.last_node(h)
        #print(last_node_h)
        assert type(last_node_h) == gambit.lib.libgambit.Node, "Last node must be a Node"
        if i == self.A:
            player_id = 0
        elif i == self.D:
            player_id = 1
        else:
            raise Exception("Invaild i")
        if last_node_h.is_terminal:
            #Expected utility of terminal node based on 5 tuple
            five_tup_prob = self.private_chance_path_i(h, i) \
            * self.private_chance_path_not_i(h, i) \
            * self.calc_pi_i(pi_i, last_node_h) \
            * self.calc_pi_not_i(pi_not_i, last_node_h)
            assert five_tup_prob <= 1 and five_tup_prob >= 0, "Five tuple probability must be between 0 and 1. It is %r" %five_tup_prob
            self.total_prob += five_tup_prob
            return last_node_h.outcome.__getitem__(i) * five_tup_prob
        if last_node_h.player == self.C:
            util = 0
            total_prob = 0
            for action_idx, action in enumerate(last_node_h.infoset.actions):
                new_h = h[:]
                new_h.append(last_node_h.children[action_idx])
                a = self.walkTree(new_h, i, pi_i, pi_not_i)

                util += action.prob * a
                total_prob += action.prob
                print("_____")
                print(action.prob)
                
            assert total_prob == 1, "Total probability of actions chance node %r can take must be equal to 1" %last_node_h
            print("UTIL")
            print(util)
            return util
        
        I = self.lookupinfosets(h)
        
        sigma = self.regretmatching(I)
        result = 0
        for action_idx, action in enumerate(last_node_h.infoset.actions):
            if last_node_h.player == i:
                #Deep copy pi_i
                pi_i_prime = self.init_pi_i(i)
                for key in pi_i.keys(): 
                    for member in range(len(pi_i_prime[key])):
                        pi_i_prime[key][member] = pi_i[key][member][:]
                        
                for node_id, node in enumerate(last_node_h.infoset.members):
                    if node == last_node_h:
                        member_idx = node_id
                        break
                #Copy h and add action a
                new_h = h[:]
                new_h.append(last_node_h.children[action_idx])
                pi_i_prime[str(last_node_h.infoset)][member_idx][action_idx] *= sigma[str(last_node_h)][str(action)]
                

                child_walk = self.walkTree(new_h, i, pi_i_prime, pi_not_i)

                #Store child_walk into mem table
                #if sigma[str(last_node_h)][str(action)] != 0:                    
                 #   self.m[player_id][str(last_node_h.infoset)][member_idx][action_idx] = child_walk / sigma[str(last_node_h)][str(action)]
                #else:
                self.m[player_id][str(last_node_h.infoset)][member_idx][action_idx] = child_walk
                #Add child's expected utility to the utility at the current infoset, after accounting for probability action was chosen
                self.u[player_id][str(last_node_h.infoset)][member_idx] += child_walk 
 
                result += child_walk
                
            else:
                #Copy pi_not_i
                if i == self.A:
                    pi_not_i_prime = self.init_pi_i(self.D)
                else:
                    pi_not_i_prime = self.init_pi_i(self.A)
                for key in pi_not_i.keys():    
                    for a in range(len(pi_not_i_prime[key])):
                        pi_not_i_prime[key][a] = pi_not_i[key][a][:]
                for node_id, node in enumerate(last_node_h.infoset.members):
                    if node == last_node_h:
                        member_idx = node_id
                        break
                pi_not_i_prime[str(last_node_h.infoset)][member_idx][action_idx] *= sigma[str(last_node_h)][str(action)]
                #Copy h and add action a
                new_h = h[:]
                new_h.append(last_node_h.children[action_idx])
                
                #Run walkTree on the child, assuming action is taken 100% of the time
                child_walk = self.walkTree(new_h, i, pi_i, pi_not_i_prime)
                #Add child's expected utility to the utility at the current infoset, after accounting for probability action was chosen
                self.u[1 - player_id][str(last_node_h.infoset)][member_idx] += child_walk
                result += child_walk
         
        if last_node_h.player == i:
            for path_idx, path in enumerate(I):
                for action_idx, action in enumerate(last_node_h.infoset.actions):
                    for node_id, node in enumerate(last_node_h.infoset.members):
                        if node == last_node_h:
                            member_idx = node_id
                            break
                    self.regret_table[str(last_node_h.infoset)][action_idx] \
                    = self.regret_table[str(last_node_h.infoset)][action_idx] \
                    + self.m[player_id][str(last_node_h.infoset)][member_idx][action_idx] \
                    - self.u[player_id][str(last_node_h.infoset)][member_idx]
                    
                    self.strategy_table[str(last_node_h.infoset)][action_idx] \
                    = self.strategy_table[str(last_node_h.infoset)][action_idx] \
                    + self.calc_pi_i(pi_i, last_node_h.children[action_idx]) * sigma[str(last_node_h)][str(action)]
        return result
    
    def solve_PCS(self, runs, save_graph = False):
        start = time.time()
        x_axis = []
        y_axis = []

        
        for t in range(runs):
            #Expected utility
            self.u = self.init_u()
            print("Run number: " + str(t + 1))
            self.total_prob = 0

            attacker_util = self.walkTree([self.g.root], self.A, self.init_pi_i(self.A), self.init_pi_i(self.D))
            self.total_prob_a = self.total_prob
            #Expected utility
            self.u = self.init_u()
            self.total_prob = 0

            defender_util = self.walkTree([self.g.root], self.D, self.init_pi_i(self.D), self.init_pi_i(self.A))
            self.total_prob_d = self.total_prob
            
            print("Run number: " + str(t+ 1) + " done")
            
            print("Sum of probabilities of reaching every terminal node for attacker: " + str(self.total_prob_a))
            print("Sum of probabilities of reaching every terminal node for defender: " + str(self.total_prob_d))
            print("Attacker Utility: " + str(attacker_util))
            print("Defender Utility: " + str(defender_util))
            print("Exploitability: " + 
                  str((attacker_util + defender_util) / 2))
            lap = time.time()
            print("Time taken: " + str(lap - start) + " seconds")
           
            x_axis.append(t + 1)
            y_axis.append((attacker_util + defender_util) / 2)

        
        self.save_results_to_csv(runs)
        plt.plot(x_axis, y_axis)
        plt.title("Exploitability over number of runs")
        plt.ylabel("Exploitability")
        plt.xlabel("Number of runs")
        if save_graph:
            plt.savefig('graphs/solve_PCS_' + self.file_name + '_' + str(runs) + '_runs.png', bbox_inches = "tight")
        plt.show()
        
        return (attacker_util, defender_util)
    
    def calc_pi_i(self, pi_i, node):
        path = self.get_path_to_node(node)
        result = 1
        for n in path:
            if n.is_terminal or n == path[-1]:
                break
            elif str(n.infoset) in pi_i.keys():
                for member_id, member in enumerate(n.infoset.members):
                    if n == member:
                        member_idx = member_id
                        break
                for child_id, child in enumerate(n.children):
                    if child in path:
                        child_idx = child_id
                        break
                result *= pi_i[str(n.infoset)][member_idx][child_idx]
        assert 0 <= result <= 1, "Probabilities must be between 0 and 1. It is %r" % result
        return result
                
    def calc_pi_not_i(self, pi_not_i, node):
        path = self.get_path_to_node(node)
        result = 1
        for n in path:
            if n.is_terminal or n == path[-1]:
                break
            elif str(n.infoset) in pi_not_i.keys():
                for member_id, member in enumerate(n.infoset.members):
                    if n == member:
                        member_idx = member_id
                        break
                for child_id, child in enumerate(n.children):
                    if child in path:
                        child_idx = child_id
                        break
                result *= pi_not_i[str(n.infoset)][member_idx][child_idx]
        assert 0 <= result <= 1, "Probabilities must be between 0 and 1. It is %r" % result
        return result
      
    #Currently unused
    '''
    def hadamard_new_u(self, new_u, player_id, last_node_h, action_idx, sigma, current):
        if current.is_terminal:
            return
        if current.player != self.C:
            current_path = self.get_path_to_node(current)
            if last_node_h in current_path and last_node_h.children[action_idx] in current_path:
                #If the current node contains the edge last_node_h and last_node_h.children[action_idx]
                sigma_a = []
                for node in current.infoset.members:
                    sigma_a.append(sigma[last_node_h.infoset][action_idx])
                    
                vector = []
                for i in range(len(new_u[player_id][current.infoset])):
                    vector.append(new_u[player_id][current.infoset][i][1])
                hadamard_vector = self.hadamard(sigma_a, vector)
                total = []
                for i in range(len(hadamard_vector)):
                    total.append((new_u[player_id][current.infoset][i][0], hadamard_vector[i]))
                new_u[player_id][current.infoset] = total   
            elif last_node_h == current:
                sigma_a = []
                for node in current.infoset.members:
                    if node == last_node_h:
                        sigma_a.append(sigma[last_node_h.infoset][action_idx])
                    else:
                        sigma_a.append(1)
                vector = []
                for i in range(len(new_u[player_id][current.infoset])):
                    vector.append(new_u[player_id][current.infoset][i][1])
                hadamard_vector = self.hadamard(sigma_a, vector)
                total = []
                for i in range(len(hadamard_vector)):
                    total.append((new_u[player_id][current.infoset][i][0], hadamard_vector[i]))
                new_u[player_id][current.infoset] = total       
        for child in current.children:
            self.hadamard_new_u(new_u, player_id, last_node_h, action_idx, sigma, child)
     '''           
    def get_average_strat(self, strategy, infoset):
        result = []
        assert strategy[infoset] != None, "Infoset does not exist in the strategy table"
        total = sum(strategy[infoset])
        if total == 0:
            for i in range(len(strategy[infoset])):
                result.append(1 / len(strategy[infoset]))            
        else:
            for prob in strategy[infoset]:
                result.append(float(prob) / float(total))
        return result
    
    def last_node(self, h):
        return h[-1]
    
    # Search all the terminal node vectors for the one we want
    def get_terminal_node_vector(self, end):
        for vector in self.terminal_node_vectors:
            if end in vector:
                return vector
        return None
    
    # To change the vector of terminal nodes to a vector of paths
    def convert_tnv_to_path_vector(self, tnv):
        #To store the paths
        path_vector = []
        for terminal_node in tnv:
            path_vector.append(self.get_path_to_node(terminal_node))
        return path_vector
    
    def get_path_to_node(self, node):
        # To store the path
        reversed_path = []
        current_node = node
        # Backtrack from the terminal node to root
        while current_node != self.g.root:
            reversed_path.append(current_node)
            current_node = current_node.parent
        reversed_path.append(current_node)
        # reversed_path currently has the path from terminal node to root
        reversed_path.reverse()
        return reversed_path #It has the correct order now
   
    #Currently unused
    '''
    # Get a vector of scalar probabilities comprising of private chance outcomes
    # for each path from the root to h for player i
    def f_c_i(self, h, i):
        tnv = self.get_terminal_node_vector(self.last_node(h))
        pv = self.convert_tnv_to_path_vector(tnv)
        result = []
        for path in pv:
            result.append(self.private_chance_path_i(path, i))
        return result
            
    
    # Get a vector of scalar probabilities comprising of public chance outcomes and 
    # private chance outcomes for each path from the root to h for player -i
    def f_c_not_i(self, h, i):
        tnv = self.get_terminal_node_vector(self.last_node(h))
        pv = self.convert_tnv_to_path_vector(tnv)
        result = []
        for path in pv:
            result.append(self.private_chance_path_not_i(path, i))
        return result
    '''   
    #To change a vector of paths to a vector of terminal nodes
    def convert_path_vector_to_tnv(self, pv):
        tnv = []
        for path in pv:
            tnv.append(path[-1])
        return tnv
        
    def private_chance_path_i(self, path, i):
        result = 1
        for node in path:
            if node.parent != None:
                if node.parent.player == self.C:
                    if (i == self.A and node.parent in self.attacker_private_chance_nodes) \
                    or (i == self.D and node.parent in self.defender_private_chance_nodes):
                        for child_idx in range(len(node.parent.children)):
                            if node.parent.children[child_idx] == node:
                                result *= node.parent.infoset.actions[child_idx].prob
                                break
        assert 0 <= result <= 1, "Probabilities must be between 0 and 1. It is %r" % result
        return result
                
    def private_chance_path_not_i(self, path, i):
        result = 1
        for node in path:
            if node.parent != None:
                if node.parent.player == self.C:
                    if (i == self.D and node.parent in self.attacker_private_chance_nodes) \
                    or (i == self.D and node.parent in self.public_chance_nodes) \
                    or (i == self.A and node.parent in self.defender_private_chance_nodes) \
                    or (i == self.A and node.parent in self.public_chance_nodes):
                        for child_idx in range(len(node.parent.children)):
                            if node.parent.children[child_idx] == node:
                                result *= node.parent.infoset.actions[child_idx].prob
                                break
        assert 0 <= result <= 1, "Probabilities must be between 0 and 1. It is %r" % result
        return result
    
    #Get a list of paths that has its last node in the infoset the last node of path belongs to 
    def lookupinfosets(self, path):
        if self.last_node(path).player == self.C:
            raise Exception("Last node must not belong to chance player")
        #Get the infoset that the last node of path is in
        ifs = self.last_node(path).infoset
        result = []
        #Iterate through each member of the infoset ifs and add the path to each node to result
        for node in ifs.members:
            result.append(self.get_path_to_node(node))
        return result
            
    #Returns a dictionary with key corresponding to each node in the infoset
    # Each value is another dictionary with keys corresponding to actions that can be taken at the infoset
    # Values of the nested dictionary correspond to the probability distribution for taking each action from the respective node
    def regretmatching(self, infoset):
        result = {}      
        ifs = self.last_node(infoset[0]).infoset
        if ifs.player == self.A or ifs.player == self.D:
            for node in ifs.members:
                i = 0
                node_dict = {}
                for action_idx, action in enumerate(ifs.actions):
                    r_plus_a = max(self.regret_table[str(ifs)][action_idx], 0)
                    r_plus_b = 0
                    for a_idx in range(len(ifs.actions)):
                        r_plus_b += max(self.regret_table[str(ifs)][a_idx], 0)
                    if r_plus_b > 0:
                        node_dict[str(action)] = r_plus_a / r_plus_b
                        i += r_plus_a / r_plus_b
                    else:
                        node_dict[str(action)] = 1.0 / float(len(ifs.actions))
                        i += 1.0 / float(len(ifs.actions))
                assert 0.9999 < i < 1.0001, "Sum of probabilities for node %r is %r" % (node, i)
                result[str(node)] = node_dict
        return result
    
    #Currently unused
    '''
    def hadamard(self, v1, v2):
        result = []
        assert type(v1) == list, "First argument must be a vector (list)"
        assert type(v2) == list, "Second argument must be a vector (list)"
        assert len(v1) == len(v2), "Both vectors must have the same dimensions, first argument has length %r and second argument has length %r" %(len(v1), len(v2))
        for idx in range(len(v1)):
            result.append(v1[idx] * v2[idx])
        return result
    '''
    def add_vector_to_dict(self, d1, v1, infosets, player):
        assert type(d1) == dict, "First argument must be a dictionary, it is a %r" %type(d1)
        assert type(v1) == list or type(v1) == dict, "Second argument must be a dictionary or a list, it is a %r" %type(v1)
        assert type(infosets) == list, "3rd argument must be a list of infosets, it is a %r" %type(infosets)
        for infoset in infosets:
            
            if type(infoset) == gambit.lib.libgambit.Infoset:
                if infoset.player != player:
                    continue
                elif infoset in d1.keys():
                    value = []
                    assert len(d1[infoset]) == len(v1[infoset]), "Length of vector in dictionary: %r does not match length of vector to be added: %r" % (len(d1[infoset]), len(v1[infoset]))
                    for i in range(len(d1[infoset])):
                        value.append((d1[infoset][i][0], d1[infoset][i][1] + v1[infoset][i][1]))
    
                    d1[infoset] = value
            elif type(infoset) == list and tuple(infoset) in d1.keys():
                value = []
                
                assert len(d1[tuple(infoset)]) == len(v1[tuple(infoset)]), "Length of vector in dictionary: %r does not match length of vector to be added: %r" % (len(d1[tuple(infoset)]), len(v1[tuple(infoset)]))
                for i in range(len(d1[tuple(infoset)])):

                    value.append((d1[tuple(infoset)][i][0], d1[tuple(infoset)][i][1] + v1[tuple(infoset)][i][1]))

                d1[tuple(infoset)] = value 
            else:
                print(infoset)
                raise Exception("Invalid infoset")
        return d1
    
    #Currently unused
    '''
    def get_attacker_expected_utility_at_node(self, strat, node):
        assert self.g != None, "Generate the game tree first!"
        utility = 0
        if node.is_terminal:
            return node.outcome.__getitem__(self.A)   #Return the payoff
        elif node.player == self.C:
            for child_idx, child in enumerate(node.children):
                # Product of the probability of the action occurring and the expected utility of choosing the action
                utility += node.infoset.actions[child_idx].prob * self.get_attacker_expected_utility_at_node(strat, child)
        elif node.player == self.A or node.player == self.D:
            for child_idx, child in enumerate(node.children):
                assert str(node.infoset) in strat.keys(), "Node %r's infoset not found in strategy table" % node
                avg_strat = self.get_average_strat(strat, str(node.infoset))
                # Product of the probability of the action occurring and the expected utility of choosing the action
                utility += avg_strat[child_idx] * self.get_attacker_expected_utility_at_node(strat, child)
        else:
            raise Exception("Player not found")           
        return utility
    
    def get_defender_expected_utility_at_node(self, strat, node):
        assert self.g != None, "Generate the game tree first!"
        utility = 0
        if node.is_terminal:
            return node.outcome.__getitem__(self.D)   #Return the payoff
        elif node.player == self.C:
            for child_idx, child in enumerate(node.children):
                # Product of the probability of the action occurring and the expected utility of choosing the action
                utility += node.infoset.actions[child_idx].prob * self.get_defender_expected_utility_at_node(strat, child)
        elif node.player == self.A or node.player == self.D:
            for child_idx, child in enumerate(node.children):
                assert str(node.infoset) in strat.keys(), "Node %r's infoset not found in strategy table" % node
                avg_strat = self.get_average_strat(strat, str(node.infoset))
                # Product of the probability of the action occurring and the expected utility of choosing the action
                utility += avg_strat[child_idx] * self.get_defender_expected_utility_at_node(strat, child)
        else:
            raise Exception("Player not found")           
        return utility
    '''
    
    #Adjust the initial server deployment values
    def plot_graph_c_infosetinit(self, tree_type, CFR = False):
        x_axis = []
        y_axis = []
        values = self.default_values
        start = time.time()
        for i in range(21):
            values[0][0] = i
            values[0][1] = 20
            self.delete_game_tree()
            x_axis.append(fraction(i, 20))
            if tree_type == 1: #Micro game tree
                solver = gambit.nash.ExternalLogitSolver()
                self.generate_micro_game_tree(values)
                tree = solver.solve(self.g)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 2: #The tree with 1 attack
                tree = self.generate_game_tree(values)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 3 and CFR == True: #Gambit can't handle the full tree
                part1 = self.generate_game_tree(values)
                tree = self.generate_game2(part1, self.default_values)
                self.init_regret_strategy_mem_tables()
                y_axis.append(self.solve_PCS(20)[0])
            else:
                raise Exception("Invalid Tree Type")
            lap = time.time()
            print("Time taken for iteration " + str(i) + ": " + str(lap - start) + " seconds")
        plt.plot(x_axis, y_axis)
        plt.title("Graph of attacker's expected payoff against chance of network deploying svr1")
        plt.ylabel("Attacker's expected payoff")
        plt.xlabel("Chance that network deploys svr1")
        plt.savefig('graphs/' + self.file_name + '_c_infosetinit.png', bbox_inches = "tight") 
        plt.show()
 
    
    #Adjust the attacker's base payoff when the attacker chooses the wrong setup    
    def plot_graph_wrong_setup(self, tree_type, CFR = False):
        x_axis = []
        y_axis = []
        values = self.default_values
        start = time.time()
        for i in range(9):
            values[1][0] = -140 + i * 10
            values[1][1] = -140 + i * 10 + 15
            values[1][2] = -140 + i * 10 + 5
            values[1][3] = -140 + i * 10 + 20
            
            self.delete_game_tree()
            
            x_axis.append(-140 + i * 10)
            if tree_type == 1: #Micro game tree
                solver = gambit.nash.ExternalLogitSolver()
                self.generate_micro_game_tree(values)
                tree = solver.solve(self.g)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 2: #The tree with 1 attack
                tree = self.generate_game_tree(values)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 3 and CFR == True: #Gambit can't handle the full tree
                part1 = self.generate_game_tree(values)
                tree = self.generate_game2(part1, self.default_values)
                self.init_regret_strategy_mem_tables()
                y_axis.append(self.solve_PCS(20)[0])
            else:
                raise Exception("Invalid Tree Type")
            lap = time.time()
            print("Time taken for iteration " + str(i) + ": " + str(lap - start) + " seconds")
        plt.plot(x_axis, y_axis)
        plt.title("Graph of attacker's expected payoff against base payoff for choosing the wrong setup")
        plt.ylabel("Attacker's expected payoff")
        plt.xlabel("Base payoff for choosing the wrong setup")
        plt.savefig('graphs/' + self.file_name + '_wrong_setup.png', bbox_inches = "tight")   
        plt.show()
        
    #Adjust the base rate of importance value  
    def plot_graph_importance_value(self, tree_type, CFR = False):
        x_axis = []
        y_axis = []
        values = self.default_values
        start = time.time()
        for i in range(21):
            values[2][0] = i * 5
            values[2][1] = i * 5 + 15
            values[2][2] = i * 5 + 5
            values[2][3] = i * 5 + 20
            
            values[3][0] = i * 5 + 10
            values[3][1] = i * 5 + 25
            values[3][2] = i * 5 + 15
            values[3][3] = i * 5 + 30
            
            self.delete_game_tree()
            
            x_axis.append(i * 5)
            if tree_type == 1: #Micro game tree
                solver = gambit.nash.ExternalLogitSolver()
                self.generate_micro_game_tree(values)
                tree = solver.solve(self.g)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 2: #The tree with 1 attack
                tree = self.generate_game_tree(values)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 3 and CFR == True: #Gambit can't handle the full tree
                part1 = self.generate_game_tree(values)
                tree = self.generate_game2(part1, self.default_values)
                self.init_regret_strategy_mem_tables()
                y_axis.append(self.solve_PCS(20)[0])
            else:
                raise Exception("Invalid Tree Type")
            lap = time.time()
            print("Time taken for iteration " + str(i) + ": " + str(lap - start) + " seconds")
        plt.plot(x_axis, y_axis)
        plt.title("Graph of attacker's expected payoff against base importance value")
        plt.ylabel("Attacker's expected payoff")
        plt.xlabel("Base importance value")
        plt.savefig('graphs/' + self.file_name + '_importance_value.png', bbox_inches = "tight")   
        plt.show()
        
    #Adjust the base rate of successful detection by the IDS   
    def plot_graph_sd_rate(self, tree_type, CFR = False):
        x_axis = []
        y_axis = []
        values = self.default_values
        start = time.time()
        for i in range(21):
            values[4][0] = i * 5
            values[4][3] = 100 - i * 5 #snd
            self.delete_game_tree()
            
            x_axis.append(float(i * 5) / float(values[4][2]))
            if tree_type == 1: #Micro game tree
                solver = gambit.nash.ExternalLogitSolver()
                self.generate_micro_game_tree(values)
                tree = solver.solve(self.g)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 2: #The tree with 1 attack
                tree = self.generate_game_tree(values)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 3 and CFR == True: #Gambit can't handle the full tree
                part1 = self.generate_game_tree(values)
                tree = self.generate_game2(part1, self.default_values)
                self.init_regret_strategy_mem_tables()
                y_axis.append(self.solve_PCS(20)[0])
            else:
                raise Exception("Invalid Tree Type")
            lap = time.time()
            print("Time taken for iteration " + str(i) + ": " + str(lap - start) + " seconds")
        plt.plot(x_axis, y_axis)
        plt.title("Graph of attacker's expected payoff against base rate of detecting successful exploits")
        plt.ylabel("Attacker's expected payoff")
        plt.xlabel("Base rate of detecting successful exploits")
        plt.savefig('graphs/' + self.file_name + '_sd_rate.png', bbox_inches = "tight")   
        plt.show()
        
     #Adjust the base rate of detecting failed exploit attempts   
    def plot_graph_fd_rate(self, tree_type, CFR = False):
        x_axis = []
        y_axis = []
        values = self.default_values
        start = time.time()
        for i in range(21):
            values[4][6] = i * 500
            values[4][9] = 10000 - i * 500 #fnd
            self.delete_game_tree()
            
            x_axis.append(float(i * 500) / float(values[4][8]))
            if tree_type == 1: #Micro game tree
                solver = gambit.nash.ExternalLogitSolver()
                self.generate_micro_game_tree(values)
                tree = solver.solve(self.g)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 2: #The tree with 1 attack
                tree = self.generate_game_tree(values)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 3 and CFR == True: #Gambit can't handle the full tree
                part1 = self.generate_game_tree(values)
                tree = self.generate_game2(part1, self.default_values)
                self.init_regret_strategy_mem_tables()
                y_axis.append(self.solve_PCS(20)[0])
            else:
                raise Exception("Invalid Tree Type")
            lap = time.time()
            print("Time taken for iteration " + str(i) + ": " + str(lap - start) + " seconds")
        plt.plot(x_axis, y_axis)
        plt.title("Graph of attacker's expected payoff against base rate of detecting failed exploit attempts")
        plt.ylabel("Attacker's expected payoff")
        plt.xlabel("Base rate of detecting failed exploit attempts")
        plt.savefig('graphs/' + self.file_name + '_fd_rate.png', bbox_inches = "tight")   
        plt.show()
        
    #Adjust the attacker's base payoff when the defender blocks    
    def plot_graph_block_base_payoff(self, tree_type, CFR = False):
        x_axis = []
        y_axis = []
        values = self.default_values
        start = time.time()
        for i in range(9):
            values[5][0] = 45 + i * 5
            self.delete_game_tree()
            
            x_axis.append(45 + i * 5)
            if tree_type == 1: #Micro game tree
                solver = gambit.nash.ExternalLogitSolver()
                self.generate_micro_game_tree(values)
                tree = solver.solve(self.g)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 2: #The tree with 1 attack
                tree = self.generate_game_tree(values)
                self.init_regret_strategy_mem_tables()
                if CFR == True:
                    y_axis.append(self.solve_PCS(200)[0])
                else:
                    y_axis.append(tree[0].payoff(self.A))
            elif tree_type == 3 and CFR == True: #Gambit can't handle the full tree
                part1 = self.generate_game_tree(values)
                tree = self.generate_game2(part1, self.default_values)
                self.init_regret_strategy_mem_tables()
                y_axis.append(self.solve_PCS(20)[0])
            else:
                raise Exception("Invalid Tree Type")
            lap = time.time()
            print("Time taken for iteration " + str(i) + ": " + str(lap - start) + " seconds")
        plt.plot(x_axis, y_axis)
        plt.title("Graph of attacker's expected payoff against attacker's base payoff when defender blocks")
        plt.ylabel("Attacker's expected payoff")
        plt.xlabel("Attacker's base payoff when defender blocks")
        plt.savefig('graphs/' + self.file_name + '_block_base_payoff.png', bbox_inches = "tight")   
        plt.show()
        
    # For saving, tuple is of the form 
    # ("NT", player, infoset number, member) if it is a non terminal node, and 
    # (parent player, infoset number, member, child_idx) if it is terminal
    def convert_node_to_tuple(self, node):
        if node.player == self.A:
            player = "A"
            infosets = self.g.players[0].infosets
        elif node.player == self.D:
            player = "D"
            infosets = self.g.players[1].infosets
        elif node.player == self.C:
            player = "C"
            infosets = self.g.players.chance.infosets
        elif node.player == None:
            if node.parent.player == self.A:
                player = "A"
                infosets = self.g.players[0].infosets
            elif node.parent.player == self.D:
                player = "D"
                infosets = self.g.players[1].infosets
            elif node.parent.player == self.C:
                player = "C"
                infosets = self.g.players.chance.infosets
            for idx in range(len(infosets)):
                if node.parent.infoset == infosets[idx]:
                    infoset_num = idx
                    for member_idx in range(len(node.parent.infoset.members)):
                        if node.parent == node.parent.infoset.members[member_idx]:
                            member_num = member_idx
                    for action_idx in range(len(node.parent.children)):
                        if node.parent.children[action_idx] == node:
                            child_idx = action_idx
                            break
                    break
            return (player, infoset_num, member_num, child_idx)
        else:
            raise Exception("Player for node not found")
        for idx in range(len(infosets)):
                if node.infoset == infosets[idx]:
                    infoset_num = idx
                    for member_idx in range(len(node.infoset.members)):
                        if infosets[idx].members[member_idx] == node:
                            member_num = member_idx
                            break
                    break
        return ("NT", player, infoset_num, member_num)
    
    def convert_list_of_nodes_to_list_of_tuples(self, l):
        result = []
        for node in l:
            result.append(self.convert_node_to_tuple(node))
        return result
    
    def convert_tnv_to_list_of_tuples(self, tnv):
        result = []
        for v in tnv:
            result.append(self.convert_list_of_nodes_to_list_of_tuples(v))
        return result
        
    def convert_tuple_to_node(self, tup):
        if tup[0] == "NT":
            if tup[1] == "A":
                infosets = self.g.players[0].infosets
            elif tup[1] == "D":
                infosets = self.g.players[1].infosets
            elif tup[1] == "C":
                infosets = self.g.players.chance.infosets
            else:
                raise Exception("Invalid player")
            return infosets[tup[2]].members[tup[3]]
        elif tup[0] == "A":
            infosets = self.g.players[0].infosets
        elif tup[0] == "D":
            infosets = self.g.players[1].infosets
        elif tup[0] == "C":
            infosets = self.g.players.chance.infosets
        else:
            print(tup[0])
            raise Exception("Invalid tuple")
        return infosets[tup[1]].members[tup[2]].children[tup[3]]
    
    def convert_list_of_tuples_to_list_of_nodes(self, l):
        result = []
        for tup in l:
            result.append(self.convert_tuple_to_node(tup))
        return result
    
    def convert_list_of_tuples_to_tnv(self, lot):
        result = []
        for t in lot:
            result.append(self.convert_list_of_tuples_to_list_of_nodes(t))
        return result
    
    def generate_micro_game_tree(self, *values):
        if list(values) == []:
            values = self.default_values
        else:
            values = values[0]
        root_node = self.g.root # Root node (initially terminal node) is always there by default.
        
        self.defender_private_chance_nodes.append(root_node)
        
        # initial infoset to represent the initial network configuration
        C_infosetinit = root_node.append_move(self.C, 2) # Num of levels server can take
        C_infosetinit.label = 'C_infosetinit'
        
        
        C_infosetinit_actions = C_infosetinit.actions
        
        '''
        for idx in range(len(C_infosetinit_actions)):
            C_infosetinit_actions[idx].label = 'svr' + str(idx + 1) # Importance value of the server
            C_infosetinit_actions[idx].prob = fraction(1, len(C_infosetinit_actions)) # prob of server having each individual value
        '''
        C_infosetinit_actions[0].label = 'svr1' # Importance value of the server
        C_infosetinit_actions[1].label = 'svr2' # Importance value of the server
        
        C_infosetinit_actions[0].prob = fraction(values[0][0], values[0][1]) # prob of server being svr1
        C_infosetinit_actions[1].prob = 1 - fraction(values[0][0], values[0][1]) # prob of server being svr2
        
        # C_infosetinit is a singleton.
        assert len(C_infosetinit.members) == 1, 'C_infosetinit is a singleton.'
        node_in_C_infosetinit = C_infosetinit.members[0]
        
        # =============================================================================
        
        Cinit_svr1 = node_in_C_infosetinit.children[0]
        Cinit_svr2 = node_in_C_infosetinit.children[1]
        
        # Connect Cinit infoset to D_infoset0_sx
        D_infoset0_svr1 = Cinit_svr1.append_move(self.D, 4)  # Num of levels honeypot can take * number of setups
        D_infoset0_svr2 = Cinit_svr2.append_move(self.D, 4)
        
        
        def update_D_infoset0_svrX(ifs, ifs_label):
            ifs.label = ifs_label
            ifs.actions[0].label = 'hp1_setup1' # honeypot disguised as server of importance 1
            ifs.actions[1].label = 'hp2_setup1' # honeypot disguised as server of importance 2
            ifs.actions[2].label = 'hp1_setup2' # honeypot disguised as server of importance 1
            ifs.actions[3].label = 'hp2_setup2' # honeypot disguised as server of importance 2
            
        update_D_infoset0_svrX(D_infoset0_svr1, 'D_infoset0_svr1')
        update_D_infoset0_svrX(D_infoset0_svr2, 'D_infoset0_svr2')
        print('g.is_perfect_recall at Cinit: {}'.format(self.g.is_perfect_recall))
        
        # =============================================================================
        # Server 1, HP 1, Setup 1
        A_infoset0 = D_infoset0_svr1.members[0].children[0].append_move(self.A, 2)
        A_infoset0.label = 'A_infoset0'
        
        A_infoset0_actions = A_infoset0.actions
        
        
        A_infoset0_actions[0].label = 'setup1' # attacker chooses to attack with setup 1 in mind
        A_infoset0_actions[1].label = 'setup2' # attacker chooses to attack with setup 2 inmind
        
        # Add the other attacker nodes into A_infoset0
        for svr in range(len(C_infosetinit.members[0].children)):
            for c in range(len(D_infoset0_svr1.members[0].children)):
                if svr == 0 and c == 0:
                    continue
                node_in_C_infosetinit.children[svr].infoset.members[0].children[c].append_move(A_infoset0)
        
        node_in_A_infoset0_svr1_hp1_setup1 = A_infoset0.members[0]
        node_in_A_infoset0_svr1_hp2_setup1 = A_infoset0.members[1]
        node_in_A_infoset0_svr1_hp1_setup2 = A_infoset0.members[2]
        node_in_A_infoset0_svr1_hp2_setup2 = A_infoset0.members[3]
        node_in_A_infoset0_svr2_hp1_setup1 = A_infoset0.members[4]
        node_in_A_infoset0_svr2_hp2_setup1 = A_infoset0.members[5]
        node_in_A_infoset0_svr2_hp1_setup2 = A_infoset0.members[6]
        node_in_A_infoset0_svr2_hp2_setup2 = A_infoset0.members[7]
        '''
        print('node_in_A_infoset0: {}'.format(node_in_A_infoset0))
        print('node_in_A_infoset0.children: {}'.format(node_in_A_infoset0.children))
        '''
        
        # Server 1
        A0_svr1_hp1_setup1_setup1 = node_in_A_infoset0_svr1_hp1_setup1.children[0]
        A0_svr1_hp1_setup1_setup2 = node_in_A_infoset0_svr1_hp1_setup1.children[1]
        
        A0_svr1_hp2_setup1_setup1 = node_in_A_infoset0_svr1_hp2_setup1.children[0]
        A0_svr1_hp2_setup1_setup2 = node_in_A_infoset0_svr1_hp2_setup1.children[1]
        
        A0_svr1_hp1_setup2_setup1 = node_in_A_infoset0_svr1_hp1_setup2.children[0]
        A0_svr1_hp1_setup2_setup2 = node_in_A_infoset0_svr1_hp1_setup2.children[1]
        
        A0_svr1_hp2_setup2_setup1 = node_in_A_infoset0_svr1_hp2_setup2.children[0]
        A0_svr1_hp2_setup2_setup2 = node_in_A_infoset0_svr1_hp2_setup2.children[1]
        
        # Server 2
        A0_svr2_hp1_setup1_setup1 = node_in_A_infoset0_svr2_hp1_setup1.children[0]
        A0_svr2_hp1_setup1_setup2 = node_in_A_infoset0_svr2_hp1_setup1.children[1]
        
        A0_svr2_hp2_setup1_setup1 = node_in_A_infoset0_svr2_hp2_setup1.children[0]
        A0_svr2_hp2_setup1_setup2 = node_in_A_infoset0_svr2_hp2_setup1.children[1]
        
        A0_svr2_hp1_setup2_setup1 = node_in_A_infoset0_svr2_hp1_setup2.children[0]
        A0_svr2_hp1_setup2_setup2 = node_in_A_infoset0_svr2_hp1_setup2.children[1]
        
        A0_svr2_hp2_setup2_setup1 = node_in_A_infoset0_svr2_hp2_setup2.children[0]
        A0_svr2_hp2_setup2_setup2 = node_in_A_infoset0_svr2_hp2_setup2.children[1]
        
        #==============================================================================
        self.set_payoff(A0_svr1_hp1_setup1_setup1, values[1][0] + 10) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr1_hp1_setup1_setup2, values[1][0]) # Attacker attacks a honeypot    
        singleton = [A0_svr1_hp1_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr1_hp1_setup1_setup1] 
        self.terminal_node_vectors.append(singleton)
        
        self.set_payoff(A0_svr1_hp2_setup1_setup1, values[1][1] + 25) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr1_hp2_setup1_setup2, values[1][1]) # Attacker attacks a honeypot
        singleton = [A0_svr1_hp2_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr1_hp2_setup1_setup1] 
        self.terminal_node_vectors.append(singleton) 
              
        self.set_payoff(A0_svr1_hp1_setup2_setup1, values[1][2]) # Attacker attacks a honeypot
        self.set_payoff(A0_svr1_hp1_setup2_setup2, values[1][2] + 15) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr1_hp1_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr1_hp1_setup2_setup2] 
        self.terminal_node_vectors.append(singleton)
        
        self.set_payoff(A0_svr1_hp2_setup2_setup1, values[1][3]) # Attacker attacks a honeypot
        self.set_payoff(A0_svr1_hp2_setup2_setup2, values[1][3] + 30) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr1_hp2_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr1_hp2_setup2_setup2] 
        self.terminal_node_vectors.append(singleton)
        
        self.set_payoff(A0_svr2_hp1_setup1_setup1, values[1][0] + 20) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr2_hp1_setup1_setup2, values[1][0]) # Attacker attacks a honeypot
        singleton = [A0_svr2_hp1_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr2_hp1_setup1_setup1] 
        self.terminal_node_vectors.append(singleton)
        
        self.set_payoff(A0_svr2_hp2_setup1_setup1, values[1][1] + 35) # Attacker's setup in mind matches the actual setup and attacks the server
        self.set_payoff(A0_svr2_hp2_setup1_setup2, values[1][1]) # Attacker attacks a honeypot
        singleton = [A0_svr2_hp2_setup1_setup2] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr2_hp2_setup1_setup1] 
        self.terminal_node_vectors.append(singleton)
        
        self.set_payoff(A0_svr2_hp1_setup2_setup1, values[1][2]) # Attacker attacks a honeypot
        self.set_payoff(A0_svr2_hp1_setup2_setup2, values[1][2] + 25) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr2_hp1_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr2_hp1_setup2_setup2] 
        self.terminal_node_vectors.append(singleton)
        
        self.set_payoff(A0_svr2_hp2_setup2_setup1, values[1][3]) # Attacker attacks a honeypot
        self.set_payoff(A0_svr2_hp2_setup2_setup2, values[1][3] + 40) # Attacker's setup in mind matches the actual setup and attacks the server
        singleton = [A0_svr2_hp2_setup2_setup1] 
        self.terminal_node_vectors.append(singleton)
        singleton = [A0_svr2_hp2_setup2_setup2] 
        self.terminal_node_vectors.append(singleton)
        print('g.is_perfect_recall at A_infoset0: {}'.format(self.g.is_perfect_recall))
        
    #def import_strat_from_csv(self, csv):
        
def read_file(file_name, gt):
    assert isinstance(gt, GameTree), "Second argument must be a GameTree object"
    with open(file_name + "_lists.txt", "rb") as f:
        combined = pickle.load(f)
    gt.g = gambit.Game.read_game(file_name + ".efg")
    gt.attacker_private_chance_nodes = gt.convert_list_of_tuples_to_list_of_nodes(combined[0])
    gt.defender_private_chance_nodes = gt.convert_list_of_tuples_to_list_of_nodes(combined[1])
    gt.public_chance_nodes = gt.convert_list_of_tuples_to_list_of_nodes(combined[2])
    gt.terminal_node_vectors = gt.convert_list_of_tuples_to_tnv(combined[3])

def read_file_array(file_name_array):
    games = []
    for file_name in file_name_array:
        games.append(read_file(file_name))
    return games


'''
#For the micro tree
gt = GameTree("game_micro2")
solver = gambit.nash.ExternalLogitSolver()
gt.generate_micro_game_tree()
gt.result = solver.solve(gt.g)
gt.write_file()
gt.init_regret_strategy_mem_tables()

result = gt.solve_PCS(100, True)
print(result)
'''
'''
gt.plot_graph_c_infosetinit(1, True)
gt.plot_graph_wrong_setup(1, True)
gt.plot_graph_importance_value(1, True)
gt.plot_graph_sd_rate(1, True)
gt.plot_graph_fd_rate(1, True)
gt.plot_graph_block_base_payoff(1, True)
'''


#For the tree with one attack
gt = GameTree("game_new2_graphPCS")
part1 = gt.generate_game_tree()

solver = gambit.nash.ExternalLogitSolver()

gt.init_regret_strategy_mem_tables()

#result = gt.solve_PCS(10, True)
#print(result)

'''
gt.plot_graph_c_infosetinit(2, False)
gt.plot_graph_wrong_setup(2, False)
gt.plot_graph_importance_value(2, False)
gt.plot_graph_sd_rate(2, False)
gt.plot_graph_fd_rate(2, False)
gt.plot_graph_block_base_payoff(2, False)
'''


gt.plot_graph_c_infosetinit(2, True)
gt.plot_graph_wrong_setup(2, True)
gt.plot_graph_importance_value(2, True)
gt.plot_graph_sd_rate(2, True)
gt.plot_graph_fd_rate(2, True)
gt.plot_graph_block_base_payoff(2, True)


'''
#For the tree with 2 attacks
gt = GameTree("game_full2")
part1 = gt.generate_game_tree()
gt.generate_game2(part1, gt.default_values)
solver = gambit.nash.ExternalLogitSolver()

gt.init_regret_strategy_mem_tables()

result = gt.solve_PCS(500, True)
print(result)
'''
'''
gt.plot_graph_c_infosetinit(3, True)
gt.plot_graph_wrong_setup(3, True)
gt.plot_graph_importance_value(3, True)
gt.plot_graph_sd_rate(3, True)
gt.plot_graph_fd_rate(3, True)
gt.plot_graph_block_base_payoff(3, True)
'''
'''
#For the tree with 2 attacks
gt = GameTree("game_full2sim")
part1 = gt.generate_game_tree()
gt.generate_game2(part1, gt.default_values)
solver = gambit.nash.ExternalLogitSolver()

gt.init_regret_strategy_mem_tables()

result = gt.solve_PCS(10, True)
print(result)
print(gt.run_sim_PCS(200000))
print(gt.run_industry_sim_PCS(200000, 0.784))
print(gt.run_industry_sim_PCS(200000, 0.514))
'''