import { Router, Request, Response } from 'express';
import { scoreAgent, scoreFromUrl, AgentProfile } from '../scanners/agent-scorer';

const router = Router();

/**
 * POST /api/score — Score an agent's security posture
 * Body: { name, codeUrl?, walletAddress?, skills?, description?, code? }
 */
router.post('/', async (req: Request, res: Response) => {
  try {
    const { name, codeUrl, walletAddress, skills, description, code } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Agent name is required' });
    }
    
    const profile: AgentProfile = {
      name,
      codeUrl,
      walletAddress,
      skills,
      description,
    };
    
    let result;
    if (code) {
      // Score with provided code
      result = scoreAgent(profile, code);
    } else if (codeUrl) {
      // Fetch and score from URL
      result = await scoreFromUrl(name, codeUrl);
    } else {
      // Score without code
      result = scoreAgent(profile);
    }
    
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: 'Score failed', details: error.message });
  }
});

/**
 * GET /api/score/leaderboard — Top scored agents (from recent scans)
 * Note: In production this would use persistent storage
 */
router.get('/leaderboard', (_req: Request, res: Response) => {
  res.json({
    message: 'Agent leaderboard — coming soon. Submit agents via POST /api/score to build the rankings.',
    totalScored: 0,
    leaderboard: [],
  });
});

export default router;
